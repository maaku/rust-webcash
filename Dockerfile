FROM rust:1.59.0-slim-bullseye as builder

RUN USER=root mkdir build
WORKDIR ./build

ADD . ./

RUN cargo build --release

FROM rust:1.59.0-slim-bullseye

ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=Etc/UTC \
    APP_USER=appuser \
    APP_PORT=8000

EXPOSE $APP_PORT

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /build/target/release/webcs ${APP}/webcs

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./webcsrv"]