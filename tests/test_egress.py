import asyncio
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from mlwsg.egress import Blocked, Guard


@asynccontextmanager
async def local_server(handler):
    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        await runner.cleanup()


def lab_guard(resolver=None, **kwargs):
    async def local_resolution(host, port):
        return ["127.0.0.1"]

    return Guard(
        resolver=resolver or local_resolution,
        lab_addresses={"public.lab": ["127.0.0.1"], "redirect.attacker.lab": ["127.0.0.1"]},
        **kwargs,
    )


def test_public_fetch_uses_validated_socket_and_original_host():
    async def scenario():
        async def handler(request):
            return web.Response(text=f"{request.host}|{request.path_qs}")

        async with local_server(handler) as port:
            result = await lab_guard().fetch(f"http://public.lab:{port}/ok?x=1")
            assert result.status == 200
            assert result.body == f"public.lab:{port}|/ok?x=1".encode()
            assert result.content_type.startswith("text/plain")

    asyncio.run(scenario())


def test_dns_change_after_validation_cannot_move_the_socket():
    async def scenario():
        lookups = 0
        hits = []

        async def handler(request):
            hits.append(request.path)
            return web.Response(text="allowed")

        async def changing_resolution(host, port):
            nonlocal lookups
            lookups += 1
            return ["127.0.0.1" if lookups == 1 else "169.254.169.254"]

        async with local_server(handler) as port:
            guard = lab_guard(changing_resolution)
            result = await guard.fetch(f"http://public.lab:{port}/ok")
            assert result.body == b"allowed"
            assert lookups == 1
            with pytest.raises(Blocked, match="DNS answer"):
                await guard.fetch(f"http://public.lab:{port}/private")
            assert hits == ["/ok"]

    asyncio.run(scenario())


def test_redirect_to_private_address_is_blocked_without_requesting_it():
    async def scenario():
        hits = []

        async def handler(request):
            hits.append(request.path)
            if request.path == "/r":
                return web.Response(status=302, headers={"Location": "/ok"})
            if request.path == "/ok":
                return web.Response(
                    status=302,
                    headers={"Location": f"http://127.0.0.1:{request.url.port}/private"},
                )
            return web.Response(text="private data")

        async with local_server(handler) as port:
            with pytest.raises(Blocked, match="outside the public lab allowlist"):
                await lab_guard().fetch(f"http://redirect.attacker.lab:{port}/r")
            assert hits == ["/r", "/ok"]

    asyncio.run(scenario())


def test_mixed_dns_answers_fail_before_any_connection():
    async def scenario():
        hits = []

        async def handler(request):
            hits.append(request.path)
            return web.Response(text="should not arrive")

        async def mixed_resolution(host, port):
            return ["127.0.0.1", "169.254.169.254"]

        async with local_server(handler) as port:
            with pytest.raises(Blocked, match="DNS answer"):
                await lab_guard(mixed_resolution).fetch(f"http://public.lab:{port}/ok")
            assert hits == []

    asyncio.run(scenario())


def test_rebinding_on_next_redirect_hop_fails_closed():
    async def scenario():
        lookups = 0
        hits = []

        async def handler(request):
            hits.append(request.path)
            return web.Response(status=302, headers={"Location": "/private"})

        async def rebinding_resolution(host, port):
            nonlocal lookups
            lookups += 1
            return ["127.0.0.1" if lookups == 1 else "10.10.0.10"]

        async with local_server(handler) as port:
            with pytest.raises(Blocked, match="DNS answer"):
                await lab_guard(rebinding_resolution).fetch(f"http://public.lab:{port}/r")
            assert lookups == 2
            assert hits == ["/r"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/token",
        "http://2852039166/token",
        "http://0xa9fea9fe/token",
        "http://0251.0376.0251.0376/token",
        "http://127.1/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://%31%36%39.254.169.254/",
        "http://trusted.example@public.lab/",
        "http://10.10.0.10\\@public.lab/",
        "file:///etc/passwd",
        "http://public.lab%2e/",
        "http://public.lab:0/",
    ],
)
def test_malformed_and_alternative_hosts_never_trigger_dns(url):
    async def scenario():
        async def forbidden_resolution(host, port):
            pytest.fail("must reject before DNS")

        with pytest.raises(Blocked):
            await lab_guard(forbidden_resolution).fetch(url)

    asyncio.run(scenario())


def test_response_body_limit_is_enforced():
    async def scenario():
        async def handler(request):
            return web.Response(body=b"123456")

        async with local_server(handler) as port:
            with pytest.raises(Blocked, match="body exceeds"):
                await lab_guard(max_body=5).fetch(f"http://public.lab:{port}/")

    asyncio.run(scenario())


def test_redirect_limit_is_enforced():
    async def scenario():
        async def handler(request):
            return web.Response(status=302, headers={"Location": "/again"})

        async with local_server(handler) as port:
            with pytest.raises(Blocked, match="redirect limit"):
                await lab_guard(max_redirects=1).fetch(f"http://public.lab:{port}/again")

    asyncio.run(scenario())
