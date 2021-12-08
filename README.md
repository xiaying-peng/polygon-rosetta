<p align="center">
  <a href="https://www.rosetta-api.org">
    <img width="90%" alt="Rosetta" src="https://www.rosetta-api.org/img/rosetta_header.png">
  </a>
</p>
<h3 align="center">
   Rosetta Polygon
</h3>
<p align="center">
  <a href="https://coveralls.io/github/maticnetwork/polygon-rosetta"><img src="https://coveralls.io/repos/github/maticnetwork/polygon-rosetta/badge.svg" /></a>
  <a href="https://goreportcard.com/report/github.com/maticnetwork/polygon-rosetta"><img src="https://goreportcard.com/badge/github.com/maticnetwork/polygon-rosetta" /></a>
  <a href="https://github.com/maticnetwork/polygon-rosetta/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/coinbase/polygon-rosetta.svg" /></a>
  <a href="https://pkg.go.dev/github.com/maticnetwork/polygon-rosetta?tab=overview"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=shield" /></a>
</p>

## Overview
`polygon-rosetta` provides an implementation of the Rosetta API for
Polygon in Golang. If you haven't heard of the Rosetta API, you can find more
information [here](https://rosetta-api.org).

## Features
* Comprehensive tracking of all MATIC balance changes
* Stateless, offline, curve-based transaction construction (with address checksum validation)
* Atomic balance lookups using go-ethereum's GraphQL Endpoint
* Idempotent access to all transaction traces and receipts

## Usage
As specified in the [Rosetta API Principles](https://www.rosetta-api.org/docs/automated_deployment.html),
all Rosetta implementations must be deployable via Docker and support running via either an
[`online` or `offline` mode](https://www.rosetta-api.org/docs/node_deployment.html#multiple-modes).

**YOU MUST INSTALL DOCKER FOR THE FOLLOWING INSTRUCTIONS TO WORK. YOU CAN DOWNLOAD
DOCKER [HERE](https://www.docker.com/get-started).**

### Install
Running the following commands will create a Docker image called `polygon-rosetta:latest`.

#### From GitHub
To download the pre-built Docker image from the latest release, run:
```text
curl -sSfL https://raw.githubusercontent.com/maticnetwork/polygon-rosetta/master/install.sh | sh -s
```

#### From Source
After cloning this repository, run the following to build the heimdall and bor node:
```text
make build-node-local
```

run the following to build the rosetta implementation:
```text
make build-rosetta-local
```

Alternatively, you can build a binary for faster testing cycles:
```text
make build-rosetta-local-bin
```

### Run
Running the following commands will start a Docker container in
[detached mode](https://docs.docker.com/engine/reference/run/#detached--d) with
a data directory at `<working directory>/polygon-data` and the Rosetta API accessible
at port `8080`.

#### Configuration Environment Variables
* `MODE` (required) - Determines if Rosetta can make outbound connections. Options: `ONLINE` or `OFFLINE`.
* `NETWORK` (required) - Polygon network to launch and/or communicate with. Options: `MAINNET` or `TESTNET`.
* `PORT`(required) - Which port to use for Rosetta.
* `BOR` (optional) - Point to a remote `bor` node instead of initializing one
* `SKIP_GETH_ADMIN` (optional, default: `FALSE`) - Instruct Rosetta to not use the `geth` `admin` RPC calls. This is typically disabled by hosted blockchain node services.
* `GETH_HEADERS` (optional) - Pass a key:value comma-separated list to be passed to the `geth` clients. e.g. `X-Auth-Token:12345-ABCDE,X-Other-Header:SomeOtherValue`

#### Mainnet:Node
```text
NETWORK=MAINNET docker-compose -p polygon -f dockerfiles/docker-compose.yml up bor heimdall
```
_If you cloned the repository, you can run `make run-node-mainnet`._

#### Testnet:Node
```text
NETWORK=TESTNET docker-compose -p polygon -f dockerfiles/docker-compose.yml up bor heimdall
```
_If you cloned the repository, you can run `make run-node-testnet`._

#### Mainnet:Online
```text
NETWORK=MAINNET docker-compose -p polygon -f dockerfiles/docker-compose.yml up rosetta
```
_If you cloned the repository, you can run `make run-mainnet-online`._

#### Mainnet:Online (Remote)
```text
NETWORK=MAINNET BOR=<NODE URL> docker-compose -p polygon -f dockerfiles/docker-compose.yml up rosetta
```
_If you cloned the repository, you can run `make run-mainnet-remote bor=<NODE_URL>`._

#### Mainnet:Offline
```text
NETWORK=MAINNET docker-compose -p polygon -f dockerfiles/docker-compose.yml up rosetta_offline
```
_If you cloned the repository, you can run `make run-mainnet-offline`._

#### Testnet:Online
```text
NETWORK=TESTNET docker-compose -p polygon -f dockerfiles/docker-compose.yml up rosetta
```
_If you cloned the repository, you can run `make run-testnet-online`._

#### Testnet:Online (Remote)
```text
NETWORK=TESTNET BOR=<NODE URL> docker-compose -p polygon -f dockerfiles/docker-compose.yml up rosetta
```
_If you cloned the repository, you can run `make run-testnet-remote bor=<NODE_URL>`._

#### Testnet:Offline
```text
NETWORK=TESTNET docker-compose -p polygon -f dockerfiles/docker-compose.yml up rosetta_offline
```
_If you cloned the repository, you can run `make run-testnet-offline`._

### Run binary
You can also run the polygon-rosetta integration locally using a binary

#### Testnet:Offline
```text
make run-bin-testnet-offline
```

#### Testnet:Online
```text
make run-bin-testnet-online bor=<NODE_URL>:8545
```

## System Requirements
`polygon-rosetta` has been tested on an [AWS c5.2xlarge instance](https://aws.amazon.com/ec2/instance-types/c5).
This instance type has 8 vCPU and 16 GB of RAM. If you use a computer with less than 16 GB of RAM,
it is possible that `polygon-rosetta` will exit with an OOM error.

### Recommended OS Settings
To increase the load `polygon-rosetta` can handle, it is recommended to tune your OS
settings to allow for more connections. On a linux-based OS, you can run the following
commands ([source](http://www.tweaked.io/guide/kernel)):
```text
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_max_syn_backlog=10000
sysctl -w net.core.somaxconn=10000
sysctl -p (when done)
```
_We have not tested `polygon-rosetta` with `net.ipv4.tcp_tw_recycle` and do not recommend
enabling it._

You should also modify your open file settings to `100000`. This can be done on a linux-based OS
with the command: `ulimit -n 100000`.

## Testing with rosetta-cli
To validate `polygon-rosetta`, [install `rosetta-cli`](https://github.com/coinbase/rosetta-cli#install)
and run one of the following commands:
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/testnet/config.json`
* `rosetta-cli check:construction --configuration-file rosetta-cli-conf/testnet/config.json`
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/mainnet/config.json`

## Future Work
* Add ERC-20 Rosetta Module to enable reading ERC-20 token transfers and transaction construction
* [Rosetta API `/mempool/*`](https://www.rosetta-api.org/docs/MempoolApi.html) implementation
* Add more methods to the `/call` endpoint (currently only support `eth_getTransactionReceipt`)
* Add CI test using `rosetta-cli` to run on each PR (likely on a regtest network)

_Please reach out on our [community](https://community.rosetta-api.org) if you want to tackle anything on this list!_

## Development
* `make deps` to install dependencies
* `make test` to run tests
* `make lint` to lint the source code
* `make salus` to check for security concerns
* `make build-local` to build a Docker image from the local context
* `make coverage-local` to generate a coverage report

## Disclaimer

### [Automated Deployment](https://www.rosetta-api.org/docs/automated_deployment.html)
> Upon first glance, using a single Dockerfile to start all services required for a particular API (i.e. the node runtime and an indexer DB) may sound antithetical. However, we have found that restricting deployment to a single container makes the orchestration of multiple nodes much easier because of coordinated start/stop and single volume mounting.

Although Rosetta Spec has strongly recommended using a **single** dockerfile 
so that the service that manages the nodes can gracefully start and stop them,
we have found out that due to the special dual-node setup with Polygon it makes
more sense to have separate dockerfiles that bootstrap each services and 
uses docker-compose to bring up all the dependencies.


## License
This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

© 2020 Coinbase
