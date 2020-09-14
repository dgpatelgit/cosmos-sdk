package types

import (
	"fmt"

	"github.com/tendermint/tendermint/crypto"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/legacy/legacytx"
)

// CountSubKeys counts the total number of keys for a multi-sig public key.
func CountSubKeys(pub crypto.PubKey) int {
	v, ok := pub.(multisig.PubKeyMultisigThreshold)
	if !ok {
		return 1
	}

	numKeys := 0
	for _, subkey := range v.PubKeys {
		numKeys += CountSubKeys(subkey)
	}

	return numKeys
}

// DefaultTxDecoder logic for standard transaction decoding
func DefaultTxDecoder(cdc *codec.LegacyAmino) sdk.TxDecoder {
	return mkDecoder(cdc.UnmarshalBinaryBare)
}

func DefaultJSONTxDecoder(cdc *codec.LegacyAmino) sdk.TxDecoder {
	return mkDecoder(cdc.UnmarshalJSON)
}

func mkDecoder(unmarshaler sdk.Unmarshaler) sdk.TxDecoder {
	return func(txBytes []byte) (sdk.Tx, error) {
		if len(txBytes) == 0 {
			return nil, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "tx bytes are empty")
		}
		var tx = legacytx.StdTx{}
		// StdTx.Msg is an interface. The concrete types
		// are registered by MakeTxCodec
		err := unmarshaler(txBytes, &tx)
		return tx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, err.Error())
	}
}

// DefaultTxEncoder logic for standard transaction encoding
func DefaultTxEncoder(cdc *codec.LegacyAmino) sdk.TxEncoder {
	return func(tx sdk.Tx) ([]byte, error) {
		return cdc.MarshalBinaryBare(tx)
	}
}

// MultiSignatureDataToAminoMultisignature converts a MultiSignatureData to an AminoMultisignature.
// Only SIGN_MODE_LEGACY_AMINO_JSON is supported.
func MultiSignatureDataToAminoMultisignature(cdc *codec.LegacyAmino, mSig *signing.MultiSignatureData) (multisig.AminoMultisignature, error) {
	n := len(mSig.Signatures)
	sigs := make([][]byte, n)

	for i := 0; i < n; i++ {
		var err error
		sigs[i], err = SignatureDataToAminoSignature(cdc, mSig.Signatures[i])
		if err != nil {
			return multisig.AminoMultisignature{}, sdkerrors.Wrapf(err, "Unable to convert Signature Data to signature %d", i)
		}
	}

	return multisig.AminoMultisignature{
		BitArray: mSig.BitArray,
		Sigs:     sigs,
	}, nil
}

// SignatureDataToAminoSignature converts a SignatureData to amino-encoded signature bytes.
// Only SIGN_MODE_LEGACY_AMINO_JSON is supported.
func SignatureDataToAminoSignature(cdc *codec.LegacyAmino, data signing.SignatureData) ([]byte, error) {
	switch data := data.(type) {
	case *signing.SingleSignatureData:
		if data.SignMode != signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON {
			return nil, fmt.Errorf("Wrong SignMode. Expected %s, got %s",
				signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, data.SignMode)
		}

		return data.Signature, nil
	case *signing.MultiSignatureData:
		aminoMSig, err := MultiSignatureDataToAminoMultisignature(cdc, data)
		if err != nil {
			return nil, err
		}

		return cdc.MarshalBinaryBare(aminoMSig)
	default:
		return nil, fmt.Errorf("Unexpected signature data %T", data)
	}
}
