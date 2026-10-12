import asyncio
import websockets


async def listen_for_events():
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


if __name__ == "__main__":
    asyncio.run(listen_for_events())

