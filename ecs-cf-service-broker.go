package main

import (
  "bytes"
  "crypto/tls"
  "encoding/json"
  "errors"
  "flag"
  "fmt"
  "io"
  "log"
  "net/http"

  "github.com/codegangsta/negroni"
  "github.com/gorilla/mux"
  "github.com/unrolled/render"
)

type Ecs struct {
  User string
  Password string
  IP string
  Namespace string
}

var ecs Ecs
var brokerUrl string
var rendering *render.Render

func ecsRequest(ecs Ecs, method string, path string, body io.Reader, headers map[string][]string) (*http.Response, error) {
  httpTransport := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  httpClient := &http.Client{Transport: httpTransport}
  reqLogin, err := http.NewRequest("GET", "https://" + ecs.IP + ":4443/login", nil)
  if err != nil {
    return nil, err
  }
  reqLogin.SetBasicAuth(ecs.User, ecs.Password)
  respLogin, err := httpClient.Do(reqLogin)
  if err != nil {
    return nil, err
  }
  token := respLogin.Header.Get("X-SDS-AUTH-TOKEN")
  if token == "" {
    return nil, errors.New("Login error")
  }
  req, err := http.NewRequest(method, "https://" + ecs.IP + ":4443" + path, body)
  if err != nil {
    return nil, err
  }
  headers["X-SDS-AUTH-TOKEN"] = []string{token}
  req.Header = headers
  resp, err := httpClient.Do(req)
  if err != nil {
    return nil, err
  }
  return resp, nil
}

type appError struct {
	err error
	status int
	json map[string]string
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  if e := fn(w, r); e != nil {
		log.Print(e.err)
		if e.status != 0 {
      rendering.JSON(w, e.status, e.json)
		}
  }
}

func RecoverHandler(next http.Handler) http.Handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    defer func() {
      if err := recover(); err != nil {
        log.Printf("panic: %+v", err)
        http.Error(w, http.StatusText(500), 500)
      }
    }()

    next.ServeHTTP(w, r)
  }
	return http.HandlerFunc(fn)
}

func main() {
  userPtr := flag.String("User", "", "The ECS namespace admin user")
  passwordPtr := flag.String("Password", "", "The ECS namespace admin password")
  ipPtr := flag.String("Endpoint", "", "The ECS IP address")
  namespacePtr := flag.String("Namespace", "", "The ECS namespace")
  brokerUrlPtr := flag.String("BrokerUrl", "", "The URL of the broker")
  flag.Parse()

  ecs = Ecs{
    User: *userPtr,
    Password: *passwordPtr,
    Namespace: *namespacePtr,
    IP: *ipPtr,
  }

  brokerUrl = *brokerUrlPtr

  port := "80"

  // See http://godoc.org/github.com/unrolled/render
  rendering = render.New()

  // See http://www.gorillatoolkit.org/pkg/mux
  router := mux.NewRouter()
  router.Handle("/v2/catalog", appHandler(GetCatalog)).Methods("GET")
  router.Handle("/v2/service_instances/{instanceId}", appHandler(Provision)).Methods("PUT")
  router.Handle("/v2/service_instances/{instanceId}/service_bindings/{bindingId}", appHandler(Bind)).Methods("PUT")
  router.Handle("/v2/service_instances/{instanceId}/service_bindings/{bindingId}", appHandler(Unbind)).Methods("DELETE")
  router.Handle("/v2/service_instances/{instanceId}", appHandler(Deprovision)).Methods("DELETE")
  router.PathPrefix("/app/").Handler(http.StripPrefix("/app/", http.FileServer(http.Dir("app"))))

	n := negroni.Classic()
	n.UseHandler(RecoverHandler(router))
	n.Run(":" + port)

	fmt.Printf("Listening on port " + port)
}

type Metadata struct {
  ImageUrl string `json:"imageUrl"`
}

type Plan struct {
	Id string `json:"id"`
  Name string `json:"name"`
  Description string `json:"description"`
  Free bool `json:"free"`
}

type Service struct {
	Id string `json:"id"`
  Name string `json:"name"`
  Description string `json:"description"`
  Bindable bool `json:"bindable"`
  Metadata Metadata `json:"metadata"`
  Plans []Plan `json:"plans"`
}

type Catalog struct {
  Services []Service `json:"services"`
}

func GetCatalog(w http.ResponseWriter, r *http.Request) *appError {
  metadata := Metadata{
    ImageUrl: brokerUrl + "/app/images/ecs.png",
  }

  plans := []Plan{
    Plan{
      Id: "unlimitedplan",
      Name: "unlimitedplan",
      Description: "Unlimited plan",
      Free: true,
    },
  }

  services := []Service{
    Service {
      Id: "ecscfservicebroker",
      Name: "ecscfservicebroker",
      Description: "ECS Service Broker",
      Bindable: true,
      Metadata: metadata,
      Plans: plans,
    },
  }

  catalog := Catalog{
    Services: services,
  }

	rendering.JSON(w, http.StatusOK, catalog)

	return nil
}

type ProvisioningRequest struct {
	ServiceId string `json:"service_id"`
  PlanId string `json:"plan_id"`
  OrganizationGuid string `json:"organization_guid"`
  SpaceGuid string `json:"space_guid"`
}

type CreateUserRequest struct {
  User string `json:"user"`
  Namespace string `json:"namespace"`
  Tags []string `json:"tags"`
}

type ProvisionResponse struct {
  DashboardUrl string `json:"dashboard_url"`
}

func Provision(w http.ResponseWriter, r *http.Request) *appError {
  vars := mux.Vars(r)
  instanceId := vars["instanceId"]
  var provisioningRequest ProvisioningRequest
  decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&provisioningRequest)
	if(err != nil) {
    return &appError{err: err, status: 422, json: map[string]string{}}
	}

  createUserRequest := CreateUserRequest{
    User: "cf-" + instanceId,
    Namespace: ecs.Namespace,
    Tags: []string{
      provisioningRequest.ServiceId,
      provisioningRequest.PlanId,
      provisioningRequest.OrganizationGuid,
      provisioningRequest.SpaceGuid,
    },
  }

  b, err := json.Marshal(createUserRequest)
  if(err != nil) {
    return &appError{err: err, status: 422, json: map[string]string{}}
	}

  headers := make(map[string][]string)
  headers["Content-Type"] = []string{"application/json"}

  resp, err := ecsRequest(ecs, "POST", "/object/users.json", bytes.NewReader(b), headers)
  if err != nil {
    return &appError{err: err, status: 422, json: map[string]string{}}
  }
  if resp.StatusCode != 201 {
    return &appError{err: errors.New("User can't be created"), status: 422, json: map[string]string{}}
  }

  provisionResponse := ProvisionResponse{
    DashboardUrl: "http://" + ecs.IP,
  }

	rendering.JSON(w, http.StatusCreated, provisionResponse)

	return nil
}

type BindingRequest struct {
  AppGuid string `json:"app_guid"`
  PlanId string `json:"plan_id"`
	ServiceId string `json:"service_id"`
}

type CreateSecretKey struct {
  Namespace string `json:"namespace"`
}

type Credentials struct {
  User string `json:"user"`
  SecretKey string `json:"secret_key"`
}

type BindingResponse struct {
  Credentials Credentials `json:"credentials"`
}

type ExistingSecretKey struct {
  SecretKey string `json:"secret_key_1"`
}

type NewSecretKey struct {
  SecretKey string `json:"secret_key"`
}

func Bind(w http.ResponseWriter, r *http.Request) *appError {
  vars := mux.Vars(r)
  instanceId := vars["instanceId"]
  var bindingRequest BindingRequest
  decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&bindingRequest)
	if(err != nil) {
    return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
	}

  secretKey := ""

  resp, err := ecsRequest(ecs, "GET", "/object/user-secret-keys/cf-" + instanceId + ".json", nil, make(map[string][]string))
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  }
  if resp.StatusCode == 200 {
    var existingSecretKey ExistingSecretKey
    decoder = json.NewDecoder(resp.Body)
  	err := decoder.Decode(&existingSecretKey)
  	if(err != nil) {
  		fmt.Println(err)
  	}
    secretKey = existingSecretKey.SecretKey
  }
  if resp.StatusCode == 404 || secretKey == "" {
    createSecretKey := CreateSecretKey{
      Namespace: ecs.Namespace,
    }

    b, err := json.Marshal(createSecretKey)
    if(err != nil) {
      return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  	}

    headers := make(map[string][]string)
    headers["Content-Type"] = []string{"application/json"}

    resp, err = ecsRequest(ecs, "POST", "/object/user-secret-keys/cf-" + instanceId + ".json", bytes.NewReader(b), headers)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
    }
    var newSecretKey NewSecretKey
    decoder = json.NewDecoder(resp.Body)
  	err = decoder.Decode(&newSecretKey)
  	if(err != nil) {
      return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  	}
    secretKey = newSecretKey.SecretKey
  } else {
    return &appError{err: errors.New("Can't get secret key"), status: http.StatusInternalServerError, json: map[string]string{}}
  }

  credentials := Credentials{
    User: "cf-" + instanceId,
    SecretKey: secretKey,
  }

  bindingResponse := BindingResponse{
    Credentials: credentials,
  }

	rendering.JSON(w, http.StatusOK, bindingResponse)

	return nil
}

type DeleteSecretKey struct {
  SecretKey string `json:"secret_key"`
  Namespace string `json:"namespace"`
}

func Unbind(w http.ResponseWriter, r *http.Request) *appError {
  vars := mux.Vars(r)
  instanceId := vars["instanceId"]

  resp, err := ecsRequest(ecs, "GET", "/object/user-secret-keys/cf-" + instanceId + ".json", nil, make(map[string][]string))
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  }

  if resp.StatusCode == 200 {
    var existingSecretKey ExistingSecretKey
    decoder := json.NewDecoder(resp.Body)
  	err := decoder.Decode(&existingSecretKey)
  	if(err != nil) {
      return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  	}
    secretKey := existingSecretKey.SecretKey

    deleteSecretKey := DeleteSecretKey{
      SecretKey: secretKey,
      Namespace: ecs.Namespace,
    }

    b, err := json.Marshal(deleteSecretKey)
    if(err != nil) {
      return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  	}

    headers := make(map[string][]string)
    headers["Content-Type"] = []string{"application/json"}

    resp, err = ecsRequest(ecs, "POST", "/object/user-secret-keys/cf-" + instanceId + "/deactivate.json", bytes.NewReader(b), headers)
    if err != nil {
      return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
    }
  }

	rendering.JSON(w, http.StatusOK, map[string]string{})

	return nil
}

type DeleteUser struct {
  User string `json:"user"`
  Namespace string `json:"namespace"`
}

func Deprovision(w http.ResponseWriter, r *http.Request) *appError {
  vars := mux.Vars(r)
  instanceId := vars["instanceId"]

  deleteUser := DeleteUser{
    User: "cf-" + instanceId,
    Namespace: ecs.Namespace,
  }

  b, err := json.Marshal(deleteUser)
  if(err != nil) {
    return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  }

  headers := make(map[string][]string)
  headers["Content-Type"] = []string{"application/json"}

  _, err = ecsRequest(ecs, "POST", "/object/users/deactivate.json", bytes.NewReader(b), headers)
  if err != nil {
    return &appError{err: err, status: http.StatusInternalServerError, json: map[string]string{}}
  }

	rendering.JSON(w, http.StatusOK, map[string]string{})

	return nil
}
