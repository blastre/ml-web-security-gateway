"""Lab-only redirect service with HTTP and a locally trusted HTTPS endpoint."""

import asyncio

import uvicorn

from mlwsg.testbed import create_testbed_app


def main() -> None:
    app = create_testbed_app("redirect")
    http = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=80))
    https = uvicorn.Server(
        uvicorn.Config(
            app,
            host="0.0.0.0",
            port=443,
            ssl_certfile="/app/lab-certs/redirect.crt",
            ssl_keyfile="/app/lab-certs/redirect.key",
        )
    )

    async def serve() -> None:
        await asyncio.gather(http.serve(), https.serve())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
