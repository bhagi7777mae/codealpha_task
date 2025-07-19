pragma solidity ^0.8.20;

contract EtherSplitter {
    event EtherDistributed(address indexed sender, uint totalAmount, uint recipients);
    event TransferSuccess(address recipient, uint amount);
    event TransferFailed(address recipient, uint amount);

    // Payable function to split Ether among recipients
    function splitEther(address[] calldata recipients) external payable {
        uint totalRecipients = recipients.length;
        require(totalRecipients > 0, "No recipients");
        require(msg.value > 0, "No Ether sent");

        uint amountPerRecipient = msg.value / totalRecipients;
        require(amountPerRecipient > 0, "Amount too small");

        for (uint i = 0; i < totalRecipients; i++) {
            // Using call to send Ether with success/fail check
            (bool sent, ) = payable(recipients[i]).call{value: amountPerRecipient}("");
            if (sent) {
                emit TransferSuccess(recipients[i], amountPerRecipient);
            } else {
                emit TransferFailed(recipients[i], amountPerRecipient);
            }
        }

        emit EtherDistributed(msg.sender, msg.value, totalRecipients);
    }
}
