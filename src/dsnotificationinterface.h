﻿// Copyright (c) 2014-2018 The Dash Core developers
// Copyright (c) 2018 The Bitsend Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITSEND_DSNOTIFICATIONINTERFACE_H
#define BITSEND_DSNOTIFICATIONINTERFACE_H

#include <validationinterface.h>

class CDSNotificationInterface : public CValidationInterface
{
public:
    CDSNotificationInterface(CConnman* connmanIn): connman(connmanIn) {}
    virtual ~CDSNotificationInterface() = default;

    // a small helper to initialize current block height in sub-modules on startup
    void InitializeCurrentBlockTip();

protected:
    // CValidationInterface
    void AcceptedBlockHeader(const CBlockIndex *pindexNew);
    void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    void SyncTransaction(const CTransaction &tx, const CBlock *pblock);

private:
    CConnman* connman;
};

#endif // BITSEND_DSNOTIFICATIONINTERFACE_H