// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 used only by RugLens local Anvil simulation tests.
contract MockERC20 {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public router;
    uint256 public buyTaxBps;
    uint256 public sellTaxBps;
    bool public honeypot;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function setRouter(address newRouter) external {
        router = newRouter;
    }

    function setTaxes(uint256 buyBps, uint256 sellBps) external {
        require(buyBps <= 10_000 && sellBps <= 10_000, "tax");
        buyTaxBps = buyBps;
        sellTaxBps = sellBps;
    }

    function setHoneypot(bool enabled) external {
        honeypot = enabled;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        uint256 tax;
        if (to == router && from != router) {
            require(!honeypot, "blocked sell");
            tax = (amount * sellTaxBps) / 10_000;
        } else if (from == router) {
            tax = (amount * buyTaxBps) / 10_000;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount - tax;
        totalSupply -= tax;
        emit Transfer(from, to, amount - tax);
    }
}

/// @notice Small V2-shaped router/pair used only in local simulation tests.
contract MockRouter {
    address public token;
    address public weth;
    uint256 public reserveNative;
    uint256 public reserveToken;

    function initialize(
        address token_,
        address weth_,
        uint256 nativeReserve_,
        uint256 tokenReserve_
    ) external {
        token = token_;
        weth = weth_;
        reserveNative = nativeReserve_;
        reserveToken = tokenReserve_;
    }

    function token0() external view returns (address) {
        return weth;
    }

    function token1() external view returns (address) {
        return token;
    }

    function getReserves() external view returns (uint112, uint112, uint32) {
        return (uint112(reserveNative), uint112(reserveToken), uint32(block.timestamp));
    }

    function getAmountsOut(uint256 amountIn, address[] calldata path)
        external
        view
        returns (uint256[] memory)
    {
        require(path.length == 2, "path");
        uint256 out;
        if (path[0] == weth && path[1] == token) {
            out = _getAmountOut(amountIn, reserveNative, reserveToken);
        } else {
            require(path[0] == token && path[1] == weth, "path");
            out = _getAmountOut(amountIn, reserveToken, reserveNative);
        }
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = out;
        return amounts;
    }

    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory) {
        require(block.timestamp <= deadline, "deadline");
        require(path.length == 2 && path[0] == weth && path[1] == token, "path");
        require(msg.value > 0, "value");
        uint256 out = _getAmountOut(msg.value, reserveNative, reserveToken);
        require(out >= amountOutMin, "slippage");
        reserveNative += msg.value;
        reserveToken -= out;
        require(MockERC20(token).transfer(to, out), "transfer");
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = msg.value;
        amounts[1] = out;
        return amounts;
    }

    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory) {
        require(block.timestamp <= deadline, "deadline");
        require(path.length == 2 && path[0] == token && path[1] == weth, "path");
        uint256 beforeBalance = MockERC20(token).balanceOf(address(this));
        require(MockERC20(token).transferFrom(msg.sender, address(this), amountIn), "transferFrom");
        uint256 received = MockERC20(token).balanceOf(address(this)) - beforeBalance;
        uint256 out = _getAmountOut(received, reserveToken, reserveNative);
        require(out >= amountOutMin, "slippage");
        reserveToken += received;
        reserveNative -= out;
        (bool ok,) = payable(to).call{value: out}("");
        require(ok, "eth transfer");
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = out;
        return amounts;
    }

    function _getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal
        pure
        returns (uint256)
    {
        require(amountIn > 0 && reserveIn > 0 && reserveOut > 0, "reserves");
        uint256 amountInWithFee = amountIn * 997;
        return (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);
    }

    receive() external payable {}
}
