import base64

from iota import ProposedTransaction, Address, Tag, TryteString
from iota import ProposedBundle
from iota import Iota

# Provide the IOTA node URL
# iota_node = "https://nodes.devnet.iota.org:443"
# iota_node = "https://127.0.0.1:5000"
iota_node = "http://mqtt.lb-1.h.chrysalis-devnet.iota.cafe:1883/"


def send_to_tangle(message, tag, previous_hashes):
    # Create an IOTA object with the specified node
    api = Iota(iota_node)
    # Convert the message to TryteString
    message_trytes = TryteString.from_string(message)
    # Generate a random address to send the transaction to
    recipient_address = Address.random(length=81)
    # Create a proposed transaction
    tx = ProposedTransaction(
        address=recipient_address,
        value=0,
        tag=Tag(tag),
        message=message_trytes
        # extra_data=previous_hashes  # Include previous hashes as extra data
    )

    # # Initialize IOTA API instance
    # api = iota.Iota("https://nodes.devnet.iota.org:443")
    # Create a new transaction object
    # tx = iota.ProposedTransaction(
    #     address=iota.Address("RECEIVER_ADDRESS"),
    #     message=iota.TryteString.from_string(base64.b64encode(data).decode()),
    #     tag=iota.Tag("SERVER"),
    #     value=0
    # )
    #
    # # Attach the previous hashes as tags to the transaction
    # tx.tag = iota.Tag(sha256_hash + md5_hash)

    # Send the transaction to the Tangle
    # response = api.send_transfer([tx])
    #
    # # Return the transaction hash
    # return response["bundle"][0].hash
    #

    # Create a proposed bundle with the transaction
    bundle = ProposedBundle()
    bundle.add_transaction(tx)

    # Send the bundle to the Tangle
    result = api.send_transfer(bundle)

    # Retrieve the transaction hash
    transaction_hash = result['bundle'].get_hash()

    return transaction_hash


# Example usage
message = "Hello, Tangle!"
tag = "MYTAG"
previous_hashes = ["PREV1HASH", "PREV2HASH"]

transaction_hash = send_to_tangle(message, tag, previous_hashes)
print("Transaction Hash:", transaction_hash)
