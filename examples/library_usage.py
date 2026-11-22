"""Use dc09-receiver as a library, with your own async callback."""

import asyncio

from dc09_receiver import Account, Config, Receiver
from dc09_receiver.sinks import CallbackSink


async def on_event(event: dict) -> None:
    # Store it, publish to MQTT, open a ticket ... whatever you need.
    print(event["account"], event["category"], event["description"])


async def main() -> None:
    config = Config(port=9500, language="en")
    config.accounts["1234"] = Account("1234", name="Demo warehouse", supervision_minutes=10)
    receiver = Receiver(config, [CallbackSink(on_event)])
    await receiver.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
