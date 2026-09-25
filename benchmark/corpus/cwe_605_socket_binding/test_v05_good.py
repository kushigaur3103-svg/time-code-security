import asyncio

async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
