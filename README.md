# Description

This Cloud Foundry Service Broker allows a user to easily use the EMCS ECS object storage.

# Build

The simplest way to build and use it is with the Dockerfile.

You just need to run the following command:

```
docker build .
```

This will create a Docker container using the golang Docker image.

# Run

Run the following command to start a container using the image you've just built:

```
docker run -d -p 80:80 <image ID> ./ecs-cf-service-broker -User=<ECS admin user> -Password=<ECS admin password> -IP=<ECS IP address> -Endpoint=<ECS endpoint that the user should use with the S3 API> -Namespace=<ECS namespace where the ECS object user should be created> -BrokerUrl=<CF Service Broker Url> -BrokerUser=<CF Service Broker User> -BrokerPassword=<CF Service Broker Password>
```

# Create

The following commands can then be used to create the Service Broker on Cloud Foundry

cf create-service-broker ecs-cf-service-broker <CF Service Broker User> <CF Service Broker Password> <CF Service Broker Url>
cf enable-service-access ecscfservicebroker

# Licensing

Licensed under the Apache License, Version 2.0 (the “License”); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
