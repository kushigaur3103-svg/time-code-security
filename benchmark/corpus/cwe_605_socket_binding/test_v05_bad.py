import asyncio

async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8888)
