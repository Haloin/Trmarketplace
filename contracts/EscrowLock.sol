// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EscrowLock {
    struct Order {
        address payable seller;
        address payable buyer;
        uint256 releaseTime;
        uint256 refundTime;
        uint256 amount;
        bool initialized;
        bool released;
        bool refunded;
    }

    mapping(bytes32 => Order) public orders;

    event OrderCreated(bytes32 indexed orderId, address indexed seller, address indexed buyer, uint256 amount, uint256 releaseTime);
    event OrderReleased(bytes32 indexed orderId, address indexed seller, uint256 amount);
    event OrderRefunded(bytes32 indexed orderId, address indexed buyer, uint256 amount);

    function create(
        bytes32 orderId,
        address payable seller,
        uint256 lockDuration
    ) external payable {
        require(!orders[orderId].initialized, "Order already exists");
        require(msg.value > 0, "Must send funds");
        require(lockDuration > 0, "Lock duration must be positive");

        uint256 releaseTime = block.timestamp + lockDuration;
        uint256 refundTime = releaseTime + lockDuration;

        orders[orderId] = Order({
            seller: seller,
            buyer: payable(msg.sender),
            releaseTime: releaseTime,
            refundTime: refundTime,
            amount: msg.value,
            initialized: true,
            released: false,
            refunded: false
        });

        emit OrderCreated(orderId, seller, msg.sender, msg.value, releaseTime);
    }

    function release(bytes32 orderId) external {
        Order storage o = orders[orderId];
        require(o.initialized, "Order does not exist");
        require(!o.released && !o.refunded, "Already settled");
        require(msg.sender == o.buyer, "Only buyer can release");

        o.released = true;
        o.seller.transfer(o.amount);

        emit OrderReleased(orderId, o.seller, o.amount);
    }

    function refund(bytes32 orderId) external {
        Order storage o = orders[orderId];
        require(o.initialized, "Order does not exist");
        require(!o.released && !o.refunded, "Already settled");
        require(msg.sender == o.buyer, "Only buyer can refund");
        require(block.timestamp >= o.refundTime, "Refund window not yet open");

        o.refunded = true;
        o.buyer.transfer(o.amount);

        emit OrderRefunded(orderId, o.buyer, o.amount);
    }

    function claimUnclaimed(bytes32 orderId) external {
        Order storage o = orders[orderId];
        require(o.initialized, "Order does not exist");
        require(!o.released && !o.refunded, "Already settled");
        require(msg.sender == o.seller, "Only seller can claim");
        require(block.timestamp >= o.releaseTime, "Release window not yet open");
        require(block.timestamp < o.refundTime, "Refund window already open, buyer may refund");

        o.released = true;
        o.seller.transfer(o.amount);

        emit OrderReleased(orderId, o.seller, o.amount);
    }

    function getOrder(bytes32 orderId) external view returns (
        address seller,
        address buyer,
        uint256 releaseTime,
        uint256 refundTime,
        uint256 amount,
        bool settled
    ) {
        Order storage o = orders[orderId];
        return (
            o.seller,
            o.buyer,
            o.releaseTime,
            o.refundTime,
            o.amount,
            o.released || o.refunded
        );
    }
}
