import asyncio
import websockets


async def test_websocket():
    async with websockets.connect(
        "ws://192.168.0.101:8000/ws/events"
    ) as websocket:

        print("Connected to NETOPS WebSocket")
        print("Waiting for events...")

        while True:
            message = await websocket.recv()
            print("")
            print("EVENT RECEIVED:")
            print(message)


asyncio.run(test_websocket())
