FROM golang:1.4
RUN git clone https://github.com/djannot/ecs-cf-service-broker.git
WORKDIR /go/ecs-cf-service-broker
RUN go get "github.com/codegangsta/negroni"
RUN go get "github.com/gorilla/mux"
RUN go get "github.com/unrolled/render"
RUN go build
