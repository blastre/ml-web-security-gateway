import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest
from aiohttp import web

from mlwsg.egress import Guard
from mlwsg.testbed import create_testbed_app


@asynccontextmanager
async def local_service(handler):
    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield site._server.sockets[0].getsockname()[1]
    finally:
        await runner.cleanup()


async def get(app, path, *, client=("127.0.0.1", 12345), params=None):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=client), base_url="http://lab"
    ) as http:
        return await http.get(path, params=params)


def test_public_redirect_metadata_and_internal_are_synthetic():
    async def scenario():
        public = await get(create_testbed_app("public"), "/ok")
        assert public.status_code == 200
        assert public.json()["message"] == "hello from the lab"
        redirected = await get(
            create_testbed_app("redirect"), "/r", params={"to": "http://169.254.169.254/"}
        )
        assert redirected.status_code == 302
        assert redirected.headers["location"] == "http://169.254.169.254/"
        metadata = await get(
            create_testbed_app("metadata"),
            "/computeMetadata/v1/instance/service-accounts/default/token",
        )
        assert metadata.status_code == 200
        assert metadata.json()["access_token"].startswith("DUMMY_")
        internal = await get(create_testbed_app("internal"), "/admin")
        assert internal.status_code == 200
        assert internal.json()["service"] == "fake-internal-admin"

    asyncio.run(scenario())


def test_protected_fetch_blocks_redirect_destination_before_connecting():
    async def scenario():
        hits = []

        async def handler(request):
            hits.append(request.path)
            return web.Response(
                status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )

        async def resolve(host, port):
            return ["127.0.0.1"]

        async with local_service(handler) as port:
            app = create_testbed_app("app")
            app.state.guard = Guard(resolver=resolve, lab_addresses={"public.lab": ["127.0.0.1"]})
            response = await get(app, "/fetch", params={"url": f"http://public.lab:{port}/r"})
            assert response.status_code == 403
            assert response.json()["stage"] == "egress"
            assert hits == ["/r"]

    asyncio.run(scenario())


def test_protected_fetch_returns_real_public_response():
    async def scenario():
        async def handler(request):
            return web.Response(text="greeting from local fixture", content_type="text/plain")

        async def resolve(host, port):
            return ["127.0.0.1"]

        async with local_service(handler) as port:
            app = create_testbed_app("app")
            app.state.guard = Guard(resolver=resolve, lab_addresses={"public.lab": ["127.0.0.1"]})
            response = await get(app, "/fetch", params={"url": f"http://public.lab:{port}/ok"})
            assert response.status_code == 200
            assert response.json() == {
                "status": 200,
                "body": "greeting from local fixture",
                "content_type": "text/plain; charset=utf-8",
            }

    asyncio.run(scenario())


def test_baseline_is_explicitly_local_and_vulnerable(monkeypatch):
    async def scenario():
        async def handler(request):
            return web.Response(text="DUMMY_LAB_PRIVATE_DATA")

        async with local_service(handler) as port:
            app = create_testbed_app("app")
            target = {"url": f"http://127.0.0.1:{port}/admin"}
            disabled = await get(app, "/unsafe-fetch", params=target)
            assert disabled.status_code == 404
            monkeypatch.setenv("MLWSG_ENABLE_UNSAFE_FETCH", "1")
            remote = await get(app, "/unsafe-fetch", client=("10.21.0.10", 12345), params=target)
            assert remote.status_code == 404
            baseline = await get(app, "/unsafe-fetch", params=target)
            assert baseline.status_code == 200
            assert baseline.json()["body"] == "DUMMY_LAB_PRIVATE_DATA"
            protected = await get(app, "/fetch", params=target)
            assert protected.status_code == 403

    asyncio.run(scenario())


def test_unknown_service_is_rejected():
    with pytest.raises(ValueError, match="unknown lab service"):
        create_testbed_app("production")
