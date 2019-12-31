pragma solidity ^0.4.0;
pragma experimental ABIEncoderV2;

import "./MerkleTree.sol";
import "./USDTToken.sol";

contract PrivateUSDT {

    USDTToken private usdtToken; // the  ERC-20 token contract

    mapping(bytes32 => bytes32) public nullifiers; // store nullifiers of spent commitments
    mapping(bytes32 => bytes32) public roots; // holds each root we've calculated so that we can pull the one relevant to the prover
    bytes32 public latestRoot; // holds the index for the latest root so that the prover can provide it later and this contract can look up the relevant root


    function PrivateUSDT(address _USDToken) {
        _owner = msg.sender;
        usdtToken = USDTToken(_USDToken);
    }

    struct SpendDescription {//384 bytes
        bytes32 value_commitment;
        bytes32 anchor;
        bytes32 nullifier;
        bytes32 rk;
        byte[64] spend_auth_sig;//64 bytes
        byte[192] proof; //192 bytes
    }

    struct OutputDescription {
        bytes32 value_commitment;
        bytes32 note_commitment;
        bytes32 epk;
        byte[192] proof;
        byte[580] c_enc;
        byte[80] c_out;
    }

    struct OutputDescriptionWithoutC {//288 bytes
        bytes32 value_commitment;
        bytes32 note_commitment;
        bytes32 epk;
        byte[192] proof;
    }

    address verifyProofContract = address(0x000F);

    function mint(uint64 value, OutputDescription calldata outputDescription, bytes32[] calldata bindingSignature) external {
        require(value > 0, "Mint negative value.");
        bytes32 signHash = keccak256(abi.encodePacked(address(this), msg.sender, value, outputDescription));

        OutputDescriptionWithoutC outputDescriptionWithoutC = OutputDescriptionWithoutC ({
            value_commitment: outputDescription.valuement,
            note_commitment: outputDescription.note_commitment,
            epk: outputDescription.epk,
            proof: outputDescription.proof
        });
        //416 = 288 + 64 + "32" + 32
        bool result = verifyProofContract.call(abi.encode(outputDescriptionWithoutC, bindingSignature, value, signHash));
        require(result, "The proof and signature have not been verified by the contract");

        // update contract states
        bytes32 commitment= outputDescription.note_commitment;
        latestRoot = insertLeaf(commitment); // recalculate the root of the merkleTree as it's now different
        roots[latestRoot] = latestRoot; // and save the new root to the list of roots

        // Finally, transfer the fTokens from the sender to this contract
        usdtToken.transferFrom(msg.sender, address(this), value);
    }


    function transfer(SpendDescription calldata spendDescription, OutputDescription[] calldata outputDescription, byte32[] calldata bindingSignature) external {

        require(roots[spendDescription.anchor] == spendDescription.anchor, "The input root has never been the root of the Merkle Tree");
        require(nullifiers[spendDescription.nullifier] == 0, "The notecommitment being spent has already been nullified!");
        require(outputDescription[0].note_commitment != outputDescription[1].note_commitment, "The new notecommitments must be different!");

        bytes32 signHash = keccak256(abi.encodePacked(address(this), msg.sender, spendDescription, outputDescription));

        OutputDescriptionWithoutC outputDescriptionWithoutC0 = OutputDescriptionWithoutC({
            value_commitment: outputDescription[0].valuement,
            note_commitment: outputDescription[0].note_commitment,
            epk: outputDescription[0].epk,
            proof: outputDescription[0].proof
            });

        OutputDescriptionWithoutC outputDescriptionWithoutC1 = OutputDescriptionWithoutC({
            value_commitment: outputDescription[1].valuement,
            note_commitment: outputDescription[1].note_commitment,
            epk: outputDescription[1].epk,
            proof: outputDescription[1].proof
            });

        //1056 = 384 + 288 + 288 + 64 + 32
        result = verifyProofContract.call(abi.encode(spendDescription, outputDescriptionWithoutC0, outputDescriptionWithoutC1, bindingSignature, signHash));
        require(result, "The proof and signature has not been verified by the contract");

        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = outputDescriptionWithoutC0.note_commitment;
        leaves[1] = outputDescriptionWithoutC1.note_commitment;

        latestRoot = insertLeaves(leaves); // recalculate the root of the merkleTree as it's now different
        roots[latestRoot] = latestRoot; // and save the new root to the list of roots

    }


    function burn(SpendDescription calldata spendDescription, uint256 payTo, uint64 value, bytes32[] calldata binding_signature) external {

        require(value > 0, "Mint negative value.");
        require(roots[spendDescription.anchor] == spendDescription.anchor, "The input root has never been the root of the Merkle Tree");
        require(nullifiers[spendDescription.nullifier] == 0, "The notecommitment being spent has already been nullified!");

        bytes32 signHash = keccak256(abi.encodePacked(address(this), msg.sender, spendDescription, payTo, value));
        // 512 = 384 + 64 + 32 + 32
        bool result = verifyProofContract.call(abi.encode(spendDescription, bindingSignature, value, signHash));
        require(result, "The proof and signature have not been verified by the contract");

        //Finally, transfer USDT from this contract to the nominated address
        address payToAddress = address(payTo);
        usdtToken.transfer(payToAddress, value);
    }

}
