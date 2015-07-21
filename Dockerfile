FROM golang:1.3
RUN git clone https://djannot:f1f5cd1cc5370c2a935d843e92863a82ccad4c15@github.com/djannot/ecs-cf-service-broker.git
WORKDIR /go/ecs-cf-service-broker
RUN go get "github.com/abbot/go-http-auth"
RUN go get "github.com/codegangsta/negroni"
RUN go get "github.com/gorilla/mux"
RUN go get "github.com/unrolled/render"
RUN go build
