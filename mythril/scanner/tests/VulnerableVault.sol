// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
// Deliberately unsafe training contract; never deploy with real funds.
contract VulnerableVault {
    constructor() payable {}
    receive() external payable {}
    function withdrawAll() external {
        (bool ok,) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok);
    }
}

