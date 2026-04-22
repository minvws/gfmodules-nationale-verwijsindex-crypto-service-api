# GFmodules Nationale Verwijsindex Crypto Service API

This app is a crypto service for the Nationale Verwijs Index (NVI) and is part of
the 'Generieke Functies, lokalisatie en addressering' project of the Ministry of Health,
Welfare and Sport of the Dutch government. This application is responsible for handling the cryptographic operations on the pseudonym from the NVI. It delegates those operations to an HSM API for secure key storage and cryptographic operations.

## NVI usage flow

The steps below describe the flow of how the NVI uses the crypto service to go from a JWE to a hashed pseudonym.:

Initially, this APP will generate in the HSM a key pair for the NVI. The private key will be used to decrypt the JWE and the public key will be registered with the PRS. This allows the PRS to encrypt the pseudonym using the NVI's public key, which can then be decrypted by the NVI using its private key.

1. NVI receives an `JWE` and `blind_factor` from a registration
2. NVI sends the `JWE` and `blind_factor` to the crypto service
3. Crypto service decrypts the `JWE` using the HSM resulting in the `blinded_pseudonym`
4. Crypto service unblinds the `blinded_pseudonym` using the `blind_factor` to obtain the final `pseudonym`
5. Crypto service hashes the `pseudonym` using the HSM
6. Crypto service returns the hashed `pseudonym` to the NVI

> [!CAUTION]
>
> ## Disclaimer
>
> This project and all associated code serve solely as **documentation and demonstration purposes**
> to illustrate potential system communication patterns and architectures.
>
> This codebase:
>
> - Is NOT intended for production use
> - Does NOT represent a final specification
> - Should NOT be considered feature-complete or secure
> - May contain errors, omissions, or oversimplified implementations
> - Has NOT been tested or hardened for real-world scenarios
>
> The code examples are *only* meant to help understand concepts and demonstrate possibilities.
>
> By using or referencing this code, you acknowledge that you do so at your own risk and that
> the authors assume no liability for any consequences of its use.

## Usage

The application is a FastAPI application, so you can use the FastAPI documentation to see how to use the application.

## Getting started

You can either run the application natively or in a docker container. If you want to run the application natively you
can take a look at the initialization steps in `docker/init.sh`.

The preferred way to run the application is through docker.

### Coordination setup

Start the docker compose from [gfmodules-coordination](https://github.com/minvws/gfmodules-coordination) when running this app as part of the overarching
gfmodules-coordination project. For full stack setup details, see the [gfmodules development readme.](https://github.com/minvws/gfmodules-coordination?tab=readme-ov-file#generic-functions-modules-generieke-functies-modules)

### Standalone setup

If you run Linux, make sure you export your user ID and group ID to synchronize permissions with the Docker user.

```bash
export NEW_UID=$(id -u)
export NEW_GID=$(id -g)
```

After this you can simply run `docker compose up`.

The application will be available at `http://localhost:8577` when the startup is completed.

## Test flow

`tools/test_flow.py` drives the full `/decrypt_and_hash` flow end-to-end: it
fetches the service's public key, blinds a sample pseudonym with `pyoprf`,
wraps it in a JWE, and calls the endpoint.

### Run

```bash
poetry install
poetry run python tools/test_flow.py                       # defaults
poetry run python tools/test_flow.py --url http://localhost:8577 --pseudonym "bsn-123"
```

On success the script prints `status=200` and a `hashed_pseudonym` body.

## Docker container builds

Build the container with:

```bash
    make container-build
```

This builds the FastAPI service image for this repository.

If you want the standalone entrypoint instead of the default one, build with the `standalone` build arg:

```bash
    docker compose build \
        --build-arg="NEW_UID=${NEW_UID}" \
        --build-arg="NEW_GID=${NEW_GID}" \
        --build-arg="standalone=true"
```

The two image variants only differ in which init script is selected.

## Contribution

As stated in the [Disclaimer](#disclaimer) this project and all associated code serve solely as documentation and
demonstration purposes to illustrate potential system communication patterns and architectures.

For that reason we will only accept contributions that fit this goal. We do appreciate any effort from the
community, but because our time is limited it is possible that your PR or issue is closed without a full justification.

If you plan to make non-trivial changes, we recommend opening an issue beforehand where we can discuss your
planned changes. This increases the chance that we might be able to use your contribution
(or it avoids doing work if there are reasons why we wouldn't be able to use it).

Note that all commits should be signed using a gpg key.

When starting to introduce changes, it is important to leave user specific files such as IDE or text-editor settings
outside the repository. For this, create a local `.gitignore` file and configure git like below.

```bash
git config --global core.excludesfile ~/.gitignore
```
