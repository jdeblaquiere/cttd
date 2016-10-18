// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/jadeblaquiere/ctcd/chaincfg"
)

// activeNetParams is a pointer to the parameters specific to the
// currently active bitcoin network.
var activeNetParams = &ctindigoNetParams

// params is used to group parameters for various networks such as the main
// network and test networks.
type params struct {
	*chaincfg.Params
	rpcPort string
}

// ctindigoNetParams contains parameters specific to the CT Indigo test network
// (wire.CTIndigoNet).
var ctindigoNetParams = params{
	Params:  &chaincfg.CTIndigoNetParams,
	rpcPort: "7765",
}

// ctredNetParams contains parameters specific to the CT Red test network
// (wire.CTRedNet).
var ctredNetParams = params{
	Params:  &chaincfg.CTRedNetParams,
	rpcPort: "17762",
}

// netName returns the name used when referring to a bitcoin network.  At the
// time of writing, btcd currently places blocks for testnet version 3 in the
// data and log directory "testnet", which does not match the Name field of the
// chaincfg parameters.  This function can be used to override this directory
// name as "testnet" when the passed active network matches wire.TestNet3.
//
// A proper upgrade to move the data and log directories for this network to
// "testnet3" is planned for the future, at which point this function can be
// removed and the network parameter's name used instead.
func netName(chainParams *params) string {
	return chainParams.Name
}
