(function () {
    var blockBookLib = undefined;

    // mnemonics is populated as required by getLanguage
    let mnemonics = {"english": new Mnemonic("english")};
    let mnemonic = mnemonics["english"];
    let network = libs.bitcoin.networks.bitcoin;
    let coin = 0;
    let foundAddressRowTemplate = $("#found-address-row-template");
    var litecoinUseLtub = true;

    let dictionaryAttackPromiseAbortController = null;

    let DOM = {};
    DOM.network = $(".network");
    DOM.blockBookUrl = $(".blockbook-url");

    DOM.bip32Client = $("#bip32-client");
    DOM.phraseNetwork = $("#network-phrase");
    DOM.useEntropy = $(".use-entropy");
    DOM.entropyContainer = $(".entropy-container");
    DOM.entropy = $(".entropy");
    DOM.entropyFiltered = DOM.entropyContainer.find(".filtered");
    DOM.entropyType = DOM.entropyContainer.find(".type");
    DOM.entropyTypeInputs = DOM.entropyContainer.find("input[name='entropy-type']");
    DOM.entropyCrackTime = DOM.entropyContainer.find(".crack-time");
    DOM.entropyEventCount = DOM.entropyContainer.find(".event-count");
    DOM.entropyBits = DOM.entropyContainer.find(".bits");
    DOM.entropyBitsPerEvent = DOM.entropyContainer.find(".bits-per-event");
    DOM.entropyWordCount = DOM.entropyContainer.find(".word-count");
    DOM.entropyBinary = DOM.entropyContainer.find(".binary");
    DOM.entropyWordIndexes = DOM.entropyContainer.find(".word-indexes");
    DOM.entropyChecksum = DOM.entropyContainer.find(".checksum");
    DOM.entropyMnemonicLength = DOM.entropyContainer.find(".mnemonic-length");
    DOM.pbkdf2Rounds = DOM.entropyContainer.find(".pbkdf2-rounds");
    DOM.pbkdf2CustomInput = DOM.entropyContainer.find("#pbkdf2-custom-input");
    DOM.pbkdf2InfosDanger = $(".PBKDF2-infos-danger");
    DOM.entropyWeakEntropyOverrideWarning = DOM.entropyContainer.find(".weak-entropy-override-warning");
    DOM.entropyFilterWarning = DOM.entropyContainer.find(".filter-warning");

    DOM.litecoinLtubContainer = $(".litecoin-ltub-container");
    DOM.litecoinUseLtub = $(".litecoin-use-ltub");

    DOM.bitcoinCashAddressTypeContainer = $(".bch-addr-type-container");
    DOM.bitcoinCashAddressType = $("[name=bch-addr-type]")

    DOM.phrase = $(".phrase");
    DOM.passphrase = $(".passphrase");
    DOM.passphraseDictionaryInput = $("#passphrase-dictionary");
    DOM.attackContainer = $(".run-attack-container");
    DOM.attackButton = $(".attack");
    DOM.stopAttackContainer = $(".stop-attack-container");
    DOM.stopAttackButton = $(".stop-attack");
    DOM.seed = $(".seed");
    DOM.rootKey = $(".root-key");

    DOM.attackBip32 = $(".attack-bip32");
    DOM.bip32DerivationPath = $(".bip32-derivation-path");
    DOM.bip32path = $("#bip32-path");

    DOM.attackBip44 = $(".attack-bip44");
    DOM.attackBip49 = $(".attack-bip49");
    DOM.attackBip84 = $(".attack-bip84");
    DOM.attackBip141 = $(".attack-bip141");
    DOM.bip141DerivationPath = $(".bip141-derivation-path");
    DOM.bip141path = $("#bip141-path");
    //DOM.bip141unavailable = $("#bip141 .unavailable");
    //DOM.bip141available = $("#bip141 .available");
    DOM.bip141semantics = $(".bip141-semantics");


    DOM.addressGap = $(".address-gap");
    DOM.accountGap = $(".account-gap");

    DOM.feedback = $(".feedback");
    DOM.foundCsv = $(".found-csv");

    DOM.languages = $(".languages a");
    DOM.foundAddresses = $(".found-addresses");

    DOM.numberOfTests = $(".number-of-tests");
    DOM.numberOfHits = $("#number-of-hits");

    function init() {
        DOM.network.on("change", networkChanged);
        DOM.bip32Client.on("change", bip32ClientChanged);
        //DOM.useEntropy.on("change", setEntropyVisibility);
        //DOM.autoCompute.on("change", delayedPhraseChanged);
        //DOM.entropy.on("input", delayedEntropyChanged);
        //DOM.entropyMnemonicLength.on("change", entropyChanged);
        //DOM.pbkdf2Rounds.on("change", pbkdf2RoundsChanged);
        //DOM.pbkdf2CustomInput.on("change", pbkdf2RoundsChanged);
        //DOM.entropyTypeInputs.on("change", entropyTypeChanged);


        DOM.attackBip32.on("change", toggleBip32);
        DOM.attackBip141.on("change", toggleBip141);
        DOM.attackButton.on("click", attackClicked);
        DOM.stopAttackButton.on("click", cancelAttackClicked)
        DOM.languages.on("click", languageChanged);

        DOM.litecoinUseLtub.on("change", litecoinUseLtubChanged);

        disableForms();
        hidePending();
        hideValidationError();
        populateNetworkSelect();
        populateClientSelect();
    }

    function networkChanged(e) {
        clearFoundAddressesList();
        DOM.litecoinLtubContainer.addClass("hidden");
        DOM.bitcoinCashAddressTypeContainer.addClass("hidden");
        var networkIndex = e.target.value;
        var network = networks[networkIndex];
        network.onSelect();
        if (network.blockBookAddress !== undefined) {
            DOM.blockBookUrl.val(network.blockBookAddress)
        } else {
            DOM.blockBookUrl.val("")
        }

    }

    function languageChanged() {
        setTimeout(function () {
            setMnemonicLanguage();
            if (DOM.phrase.val().length > 0) {
                var newPhrase = convertPhraseToNewLanguage();
                DOM.phrase.val(newPhrase);
            }
        }, 50);
    }


    function toggleBip32() {
        if (DOM.attackBip32.is(':checked')) {
            DOM.bip32DerivationPath.removeClass('hidden');
        } else {
            DOM.bip32DerivationPath.addClass('hidden');
        }
    }

    function toggleBip141() {
        if (DOM.attackBip141.is(':checked')) {
            DOM.bip141DerivationPath.removeClass('hidden');
        } else {
            DOM.bip141DerivationPath.addClass('hidden');
        }
    }

    function toggleAttackButton() {
        if (dictionaryAttackPromiseAbortController != null) {
            DOM.attackContainer.addClass('hidden');
            DOM.stopAttackContainer.removeClass('hidden');
        } else {
            DOM.stopAttackContainer.addClass('hidden');
            DOM.attackContainer.removeClass('hidden');
        }
    }

    function litecoinUseLtubChanged() {
        litecoinUseLtub = DOM.litecoinUseLtub.prop("checked");
        if (litecoinUseLtub) {
            network = libs.bitcoin.networks.litecoin;
        } else {
            network = libs.bitcoin.networks.litecoinXprv;
        }
    }

    function bip32ClientChanged(e) {
        var clientIndex = DOM.bip32Client.val();
        if (clientIndex == "custom") {
            DOM.bip32path.prop("readonly", false);
        } else {
            DOM.bip32path.prop("readonly", true);
            clients[clientIndex].onSelect();
            //rootKeyChanged();
        }
    }

    function stopRunningAttack() {
        if (dictionaryAttackPromiseAbortController != null) {
            dictionaryAttackPromiseAbortController.abort("Stop running attack button clicked");
            dictionaryAttackPromiseAbortController = null;
        }
    }

    function attackClicked() {
        stopRunningAttack();
        clearFoundAddressesList();
        showRunningAttack();

        dictionaryAttackPromiseAbortController = new AbortController()
        toggleAttackButton();
        runDictionaryAttackAsync(dictionaryAttackPromiseAbortController.signal)
    }

    function cancelAttackClicked() {
        stopRunningAttack();
        showStoppedRunningAttack();
        toggleAttackButton();
    }

    function setTimeoutAwait(fn, timeout) {
        return new Promise((resolve, reject) => {
            setTimeout(async () => {
                fn();
                resolve();
            }, timeout)
        });
    }

    function getTypes() {
        let types = []
        if (DOM.attackBip32.is(':checked')) {
            types.push("bip32")
        }

        if (DOM.attackBip44.is(':checked')) {
            types.push("bip44")
        }

        if (DOM.attackBip49.is(':checked')) {
            types.push("bip49")
        }

        if (DOM.attackBip84.is(':checked')) {
            types.push("bip84")
        }

        if (DOM.attackBip141.is(':checked')) {
            types.push("bip141")
        }

        return types;
    }

    async function runDictionaryAttackAsync(abortSignal) {
        const startCurrentDate = Date.now();

        let numberOfHits = 0;
        let numberOfTests = 0;

        setMnemonicLanguage();
        let phrase = DOM.phrase.val();
        let errorText = findPhraseErrors(phrase);
        if (errorText) {
            showValidationError(errorText);
            dictionaryAttackPromiseAbortController = null;
            toggleAttackButton();
            return;
        }

        if (DOM.passphraseDictionaryInput[0].files.length === 0) {
            showValidationError("You need to provide dictionary to run the attack");
            dictionaryAttackPromiseAbortController = null;
            toggleAttackButton();
            return;
        }

        // TODO: validate blockbook url?
        let blockBookUrl = DOM.blockBookUrl.val()
        if (blockBookUrl === "") {
            showValidationError("You need to provide the blockbook URL");
            dictionaryAttackPromiseAbortController = null;
            toggleAttackButton();
            return;
        }

        blockBookUrl = blockBookUrl.replace("http", "ws")
        if (blockBookUrl.endsWith("/")) {
            blockBookUrl = blockBookUrl.slice(0, blockBookUrl.length - 1);
        }
        blockBookLib = new BlockbookWebSocketLib(`${blockBookUrl}/websocket`)

        let types = getTypes()

        if (types.length === 0) {
            showValidationError("Select at least one type of derivation paths");
            dictionaryAttackPromiseAbortController = null;
            toggleAttackButton();
            return
        }

        abortSignal.throwIfAborted();

        const file = DOM.passphraseDictionaryInput[0].files[0];
        const dictionary = new DictionaryReader(file);
        for await (const passphrase of dictionary.getWords()) {
            updatePassphrase(passphrase)
            console.log("Passphrase: " + passphrase);
            let found = await (calculateAddressesAndCheck(phrase, passphrase, types));
            if (found) {
                numberOfHits++;
                DOM.numberOfHits.text(`${numberOfHits}`)
            }
            numberOfTests++;
            DOM.numberOfTests.text(`${numberOfTests}`)
            abortSignal.throwIfAborted();
        }

        const endCurrentDate = Date.now();
        const took = endCurrentDate - startCurrentDate;

        showAttackDone(took);
        dictionaryAttackPromiseAbortController = null;
        toggleAttackButton();
    }

    function updatePassphrase(passphrase) {
        DOM.passphrase.attr("readonly", false);
        DOM.passphrase.val(passphrase)
        DOM.passphrase.attr("readonly", true);
    }

    function updateSeed(seed) {
        DOM.seed.attr("readonly", false);
        DOM.seed.val(seed)
        DOM.seed.attr("readonly", true);
    }

    async function calculateAddressesAndCheck(phrase, passphrase, types) {
        // Calculate and display
        const addressGap = DOM.addressGap.val();
        const accountGap = DOM.accountGap.val();

        let promises = []
        for (let type of types) {
            const typeAccountGap = derivationPathContainsAccount(type) ? accountGap : 1;

            const [seedFromMnemonic, rootKey] = calcBip32RootKeyFromSeed(type, phrase, passphrase);

            updateSeed(seedFromMnemonic);
            //DOM.rootKey.val(rootKey.toBase58())

            for (let account = 0; account < typeAccountGap; account++) {
                // TODO: Should we also check change 1?
                promises.push(calcForDerivationPath(seedFromMnemonic, rootKey, type, account, 0, addressGap));
            }
        }

        let found = false;
        let listOfResults = await Promise.all(promises)
        for (let results of listOfResults) {
            if (results !== undefined) {
                for (let result of results) {
                    addAddressToFoundList(passphrase, result[0], result[1], result[2], result[3]);
                    found = true;
                }
            }
        }
        return found;

        //calcBip85();
        // Show the word indexes
        //showWordIndexes();
        //writeSplitPhrase(phrase);
    }

    async function calcForDerivationPath(seed, bip32RootKey, type, account, change, addressGap) {
        // Don't show segwit if it's selected but network doesn't support it
        //TODO: Check this somewhere else
        //if (segwitSelected() && !networkHasSegwit()) {
        //    showSegwitUnavailable();
        //    hidePending();
        //    return;
        //}
        //showSegwitAvailable();

        // Get the derivation path
        const derivationPath = getDerivationPath(type, account, change);
        const accountDerivationPath = getDerivationPath(type, account, undefined);
        const errorText = findDerivationPathErrors(derivationPath, bip32RootKey);
        if (errorText) {
            showValidationError(errorText);
            return undefined;
        }

        const bip32ExtendedKey = calcBip32ExtendedKey(derivationPath, bip32RootKey);

        let accountXprv, accountXpub;
        if (type === "bip44") {
            [accountXprv, accountXpub] = calculateBip44Keys(accountDerivationPath, bip32RootKey);
            let result = await checkXPub(accountXpub);
            if (result[0]) {
                return result[1].map(addressResult => [addressResult["path"], addressResult["address"], "-", "-"])
            }
            return []
        } else if (type === "bip49") {
            [accountXprv, accountXpub] = calculateBip49Keys(accountDerivationPath, bip32RootKey);
            let result = await checkXPub(accountXpub);
            if (result[0]) {
                return result[1].map(addressResult => [addressResult["path"], addressResult["address"], "-", "-"])
            }
            return []
        } else if (type === "bip84") {
            [accountXprv, accountXpub] = calculateBip84Keys(accountDerivationPath, bip32RootKey);
            let result = await checkXPub(accountXpub);
            if (result[0]) {
                return result[1].map(addressResult => [addressResult["path"], addressResult["address"], "-", "-"])
            }
            return []
        } else if (type === "bip84") {
            [accountXprv, accountXpub] = calculateBip84Keys(accountDerivationPath, bip32RootKey);
            let result = await checkXPub(accountXpub);
            if (result[0]) {
                return result[1].map(addressResult => [addressResult["path"], addressResult["address"], "-", "-"])
            }
            return []
        } else {
            [extendedPrivKey, extendedPubKey] = calculateBip32(bip32RootKey, bip32ExtendedKey);
            return (await checkAddresses(type, seed, bip32ExtendedKey, addressGap))
                .map(result => [`${derivationPath}/${result[0]}`, result[1], result[2], result[3]]);
        }
    }

    function calculateBip44Keys(accountDerivationPath, bip32RootKey) {
        const accountExtendedKey = calcBip32ExtendedKey(accountDerivationPath, bip32RootKey);
        const accountXprv = accountExtendedKey.toBase58();
        const accountXpub = accountExtendedKey.neutered().toBase58();
        //if (isELA()) {
        //             displayBip44InfoForELA();
        //}
        return [accountXprv, accountXpub];
    }

    function calculateBip49Keys(accountDerivationPath, bip32RootKey) {
        const accountExtendedKey = calcBip32ExtendedKey(accountDerivationPath, bip32RootKey);
        const accountXprv = accountExtendedKey.toBase58();
        const accountXpub = accountExtendedKey.neutered().toBase58();
        return [accountXprv, accountXpub];
    }

    function calculateBip84Keys(accountDerivationPath, bip32RootKey) {
        const accountExtendedKey = calcBip32ExtendedKey(accountDerivationPath, bip32RootKey);
        const accountXprv = accountExtendedKey.toBase58();
        const accountXpub = accountExtendedKey.neutered().toBase58();
        return [accountXprv, accountXpub];
    }

    function calculateBip32(bip32RootKey, bip32ExtendedKey) {
        let xprvkeyB58 = "NA";
        if (!bip32ExtendedKey.isNeutered()) {
            xprvkeyB58 = bip32ExtendedKey.toBase58();
        }
        const extendedPrivKey = xprvkeyB58;
        const extendedPubKey = bip32ExtendedKey.neutered().toBase58();
        //if (isELA()) {
        //             displayBip32InfoForELA();
        //}
        return [extendedPrivKey, extendedPubKey]
    }

    async function checkAddress(address, pubkey, privkey) {
        console.log("Checking " + address)
        const transactions = await blockBookLib.getTransactionsByAddressAsync(address)
        if (transactions.success && transactions.result.length > 0) {
            console.log("address found: " + address)
            return true;
        }
        return false;
    }

    async function checkXPub(xpubkey) {
        console.log("Checking " + xpubkey)
        const transactionsResult = await blockBookLib.getTransactionsAndAddressesByXPubAsync(xpubkey)
        if (transactionsResult.success) {
            if (transactionsResult.result["txids"].length > 0) {
                console.log("xpub found: " + xpubkey)
                return [true, transactionsResult.result["addresses"]];
            }
        } else {
            console.log("ERROR!")
            console.log(transactionsResult.error)
        }
        return [false, undefined];
    }

    async function checkAddresses(type, seed, bip32ExtendedKey, gap) {
        promises = []
        max = gap
        for (let i = 0; i < max; i++) {
            promises.push(
                async function () {
                    const res = await calculateAddress(type, seed, bip32ExtendedKey, i);
                    if (res === undefined) {
                        return []
                    }
                    const [address, pubkey, privkey] = res
                    const result = await checkAddress(address, pubkey, privkey)
                    return [result, i, address, pubkey, privkey];
                }()
            )
        }

        const results = (await Promise.all(promises))
            .filter(result => result.length > 0 && result[0] === true)
            .map(result => [result[1], result[2], result[3], result[4]])

        console.log(results)

        return results
    }

    async function calculateAddress(type, seed, bip32ExtendedKey, index, useHardenedAddresses = false) {
        const isSegwit = segwitSelected(type);
        const segwitAvailable = networkHasSegwit(type);
        const isP2wpkh = p2wpkhSelected(type);
        const isP2wpkhInP2sh = p2wpkhInP2shSelected(type);
        const isP2wsh = p2wshSelected(type);
        const isP2wshInP2sh = p2wshInP2shSelected(type);

        const useBip38 = false;
        const bip38password = "";

        // derive HDkey for this row of the table
        var key = "NA";
        if (useHardenedAddresses) {
            key = bip32ExtendedKey.deriveHardened(index);
        } else {
            key = bip32ExtendedKey.derive(index);
        }
        // bip38 requires uncompressed keys
        // see https://github.com/iancoleman/bip39/issues/140#issuecomment-352164035
        var keyPair = key.keyPair;
        var useUncompressed = useBip38;
        if (useUncompressed) {
            keyPair = new libs.bitcoin.ECPair(keyPair.d, null, {network: getNetwork(type), compressed: false});
            if (isGRS())
                keyPair = new libs.groestlcoinjs.ECPair(keyPair.d, null, {
                    network: getNetwork(type),
                    compressed: false
                });

        }
        // get address
        var address = keyPair.getAddress().toString();
        // get privkey
        var hasPrivkey = !key.isNeutered();
        var privkey = "NA";
        if (hasPrivkey) {
            privkey = keyPair.toWIF();
            // BIP38 encode private key if required
            if (useBip38) {
                if (isGRS())
                    privkey = libs.groestlcoinjsBip38.encrypt(keyPair.d.toBuffer(), false, bip38password, function (p) {
                        console.log("Progressed " + p.percent.toFixed(1) + "% for index " + index);
                    }, null, networks[DOM.network.val()].name.includes("Testnet"));
                else
                    privkey = libs.bip38.encrypt(keyPair.d.toBuffer(), false, bip38password, function (p) {
                        console.log("Progressed " + p.percent.toFixed(1) + "% for index " + index);
                    });
            }
        }
        // get pubkey
        var pubkey = keyPair.getPublicKeyBuffer().toString('hex');
        // Ethereum values are different
        if (networkIsEthereum()) {
            var pubkeyBuffer = keyPair.getPublicKeyBuffer();
            var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
            var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
            var hexAddress = addressBuffer.toString('hex');
            var checksumAddress = libs.ethUtil.toChecksumAddress(hexAddress);
            address = libs.ethUtil.addHexPrefix(checksumAddress);
            pubkey = libs.ethUtil.addHexPrefix(pubkey);
            if (hasPrivkey) {
                privkey = libs.ethUtil.bufferToHex(keyPair.d.toBuffer(32));
            }
        }
        //TRX is different
        if (networks[DOM.network.val()].name == "TRX - Tron") {
            keyPair = new libs.bitcoin.ECPair(keyPair.d, null, {network: getNetwork(type), compressed: false});
            var pubkeyBuffer = keyPair.getPublicKeyBuffer();
            var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
            var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
            address = libs.bitcoin.address.toBase58Check(addressBuffer, 0x41);
            if (hasPrivkey) {
                privkey = keyPair.d.toBuffer().toString('hex');
            }
        }

        // RSK values are different
        if (networkIsRsk()) {
            var pubkeyBuffer = keyPair.getPublicKeyBuffer();
            var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
            var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
            var hexAddress = addressBuffer.toString('hex');
            // Use chainId based on selected network
            // Ref: https://developers.rsk.co/rsk/architecture/account-based/#chainid
            var chainId;
            var rskNetworkName = networks[DOM.network.val()].name;
            switch (rskNetworkName) {
                case "R-BTC - RSK":
                    chainId = 30;
                    break;
                case "tR-BTC - RSK Testnet":
                    chainId = 31;
                    break;
                default:
                    chainId = null;
            }
            var checksumAddress = toChecksumAddressForRsk(hexAddress, chainId);
            address = libs.ethUtil.addHexPrefix(checksumAddress);
            pubkey = libs.ethUtil.addHexPrefix(pubkey);
            if (hasPrivkey) {
                privkey = libs.ethUtil.bufferToHex(keyPair.d.toBuffer());
            }
        }

        // Handshake values are different
        if (networks[DOM.network.val()].name == "HNS - Handshake") {
            var ring = libs.handshake.KeyRing.fromPublic(keyPair.getPublicKeyBuffer())
            address = ring.getAddress().toString();
        }

        // Stellar is different
        if (networks[DOM.network.val()].name == "XLM - Stellar") {
            var purpose = 44;
            var path = "m/";
            path += purpose + "'/";
            path += coin + "'/" + index + "'";
            var keypair = libs.stellarUtil.getKeypair(path, seed);
            privkey = keypair.secret();
            pubkey = address = keypair.publicKey();
        }

        // Nano currency
        if (networks[DOM.network.val()].name == "NANO - Nano") {
            var nanoKeypair = libs.nanoUtil.getKeypair(index, seed);
            privkey = nanoKeypair.privKey;
            pubkey = nanoKeypair.pubKey;
            address = nanoKeypair.address;
        }

        if ((networks[DOM.network.val()].name == "NAS - Nebulas")) {
            var privKeyBuffer = keyPair.d.toBuffer(32);
            var nebulasAccount = libs.nebulas.Account.NewAccount();
            nebulasAccount.setPrivateKey(privKeyBuffer);
            address = nebulasAccount.getAddressString();
            privkey = nebulasAccount.getPrivateKeyString();
            pubkey = nebulasAccount.getPublicKeyString();
        }
        // Ripple values are different
        if (networks[DOM.network.val()].name == "XRP - Ripple") {
            privkey = convertRipplePriv(privkey);
            address = convertRippleAdrr(address);
        }
        // Jingtum values are different
        if (networks[DOM.network.val()].name == "SWTC - Jingtum") {
            privkey = convertJingtumPriv(privkey);
            address = convertJingtumAdrr(address);
        }
        // CasinoCoin values are different
        if (networks[DOM.network.val()].name == "CSC - CasinoCoin") {
            privkey = convertCasinoCoinPriv(privkey);
            address = convertCasinoCoinAdrr(address);
        }
        // Bitcoin Cash address format may vary
        if (networks[DOM.network.val()].name == "BCH - Bitcoin Cash") {
            var bchAddrType = DOM.bitcoinCashAddressType.filter(":checked").val();
            if (bchAddrType == "cashaddr") {
                address = libs.bchaddr.toCashAddress(address);
            } else if (bchAddrType == "bitpay") {
                address = libs.bchaddr.toBitpayAddress(address);
            }
        }
        // Bitcoin Cash address format may vary
        if (networks[DOM.network.val()].name == "SLP - Simple Ledger Protocol") {
            var bchAddrType = DOM.bitcoinCashAddressType.filter(":checked").val();
            if (bchAddrType == "cashaddr") {
                address = libs.bchaddrSlp.toSlpAddress(address);
            }
        }

        // ZooBC address format may vary
        if (networks[DOM.network.val()].name == "ZBC - ZooBlockchain") {

            var purpose = 44;
            var path = "m/";
            path += purpose + "'/";
            path += coin + "'/" + index + "'";
            var result = libs.zoobcUtil.getKeypair(path, seed);

            let publicKey = result.pubKey.slice(1, 33);
            let privateKey = result.key;

            privkey = privateKey.toString('hex');
            pubkey = publicKey.toString('hex');

            address = libs.zoobcUtil.getZBCAddress(publicKey, 'ZBC');
        }

        // Segwit addresses are different
        if (isSegwit) {
            if (!segwitAvailable) {
                return;
            }
            if (isP2wpkh) {
                var keyhash = libs.bitcoin.crypto.hash160(key.getPublicKeyBuffer());
                var scriptpubkey = libs.bitcoin.script.witnessPubKeyHash.output.encode(keyhash);
                address = libs.bitcoin.address.fromOutputScript(scriptpubkey, getNetwork(type))
            } else if (isP2wpkhInP2sh) {
                var keyhash = libs.bitcoin.crypto.hash160(key.getPublicKeyBuffer());
                var scriptsig = libs.bitcoin.script.witnessPubKeyHash.output.encode(keyhash);
                var addressbytes = libs.bitcoin.crypto.hash160(scriptsig);
                var scriptpubkey = libs.bitcoin.script.scriptHash.output.encode(addressbytes);
                address = libs.bitcoin.address.fromOutputScript(scriptpubkey, getNetwork(type))
            } else if (isP2wsh) {
                // https://github.com/libs.bitcoinjs-lib/blob/v3.3.2/test/integration/addresses.js#L71
                // This is a 1-of-1
                var witnessScript = libs.bitcoin.script.multisig.output.encode(1, [key.getPublicKeyBuffer()]);
                var scriptPubKey = libs.bitcoin.script.witnessScriptHash.output.encode(libs.bitcoin.crypto.sha256(witnessScript));
                address = libs.bitcoin.address.fromOutputScript(scriptPubKey, getNetwork(type));
            } else if (isP2wshInP2sh) {
                // https://github.com/libs.bitcoinjs-lib/blob/v3.3.2/test/integration/transactions.js#L183
                // This is a 1-of-1
                var witnessScript = libs.bitcoin.script.multisig.output.encode(1, [key.getPublicKeyBuffer()]);
                var redeemScript = libs.bitcoin.script.witnessScriptHash.output.encode(libs.bitcoin.crypto.sha256(witnessScript));
                var scriptPubKey = libs.bitcoin.script.scriptHash.output.encode(libs.bitcoin.crypto.hash160(redeemScript));
                address = libs.bitcoin.address.fromOutputScript(scriptPubKey, getNetwork(type))
            }
        }

        if ((networks[DOM.network.val()].name == "CRW - Crown")) {
            address = libs.bitcoin.networks.crown.toNewAddress(address);
        }

        if (networks[DOM.network.val()].name == "EOS - EOSIO") {
            address = ""
            pubkey = EOSbufferToPublic(keyPair.getPublicKeyBuffer());
            privkey = EOSbufferToPrivate(keyPair.d.toBuffer(32));
        }

        if (networks[DOM.network.val()].name == "FIO - Foundation for Interwallet Operability") {
            address = ""
            pubkey = FIObufferToPublic(keyPair.getPublicKeyBuffer());
            privkey = FIObufferToPrivate(keyPair.d.toBuffer(32));
        }

        if (networks[DOM.network.val()].name == "ATOM - Cosmos Hub") {
            const hrp = "cosmos";
            address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
            pubkey = CosmosBufferToPublic(keyPair.getPublicKeyBuffer(), hrp);
            privkey = keyPair.d.toBuffer().toString("base64");
        }

        if (networks[DOM.network.val()].name == "RUNE - THORChain") {
            const hrp = "thor";
            address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
            pubkey = keyPair.getPublicKeyBuffer().toString("hex");
            privkey = keyPair.d.toBuffer().toString("hex");
        }

        if (networks[DOM.network.val()].name == "XWC - Whitecoin") {
            address = XWCbufferToAddress(keyPair.getPublicKeyBuffer());
            pubkey = XWCbufferToPublic(keyPair.getPublicKeyBuffer());
            privkey = XWCbufferToPrivate(keyPair.d.toBuffer(32));
        }

        if (networks[DOM.network.val()].name == "LUNA - Terra") {
            const hrp = "terra";
            address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
            pubkey = keyPair.getPublicKeyBuffer().toString("hex");
            privkey = keyPair.d.toBuffer().toString("hex");
        }

        if (networks[DOM.network.val()].name == "IOV - Starname") {
            const hrp = "star";
            address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
            pubkey = CosmosBufferToPublic(keyPair.getPublicKeyBuffer(), hrp);
            privkey = keyPair.d.toBuffer().toString("base64");
        }

        //Groestlcoin Addresses are different
        if (isGRS()) {

            if (isSegwit) {
                if (!segwitAvailable) {
                    return;
                }
                if (isP2wpkh) {
                    address = libs.groestlcoinjs.address.fromOutputScript(scriptpubkey, getNetwork(type))
                } else if (isP2wpkhInP2sh) {
                    address = libs.groestlcoinjs.address.fromOutputScript(scriptpubkey, getNetwork(type))
                }
            }
            //non-segwit addresses are handled by using groestlcoinjs for bip32RootKey
        }

        if (isELA()) {
            let elaAddress = calcAddressForELA(
                seed,
                parseIntNoNaN(DOM.bip44coin.val(), 0),
                parseIntNoNaN(DOM.bip44account.val(), 0),
                parseIntNoNaN(DOM.bip44change.val(), 0),
                index
            );
            address = elaAddress.address;
            privkey = elaAddress.privateKey;
            pubkey = elaAddress.publicKey;
        }

        return [address, pubkey, privkey];
    }

    function networkIsEthereum() {
        var name = networks[DOM.network.val()].name;
        return (name == "ETH - Ethereum")
            || (name == "ETC - Ethereum Classic")
            || (name == "EWT - EnergyWeb")
            || (name == "PIRL - Pirl")
            || (name == "MIX - MIX")
            || (name == "MOAC - MOAC")
            || (name == "MUSIC - Musicoin")
            || (name == "POA - Poa")
            || (name == "EXP - Expanse")
            || (name == "CLO - Callisto")
            || (name == "DXN - DEXON")
            || (name == "ELLA - Ellaism")
            || (name == "ESN - Ethersocial Network")
            || (name == "VET - VeChain")
            || (name == "ERE - EtherCore")
            || (name == "BSC - Binance Smart Chain")
    }

    function networkIsRsk() {
        var name = networks[DOM.network.val()].name;
        return (name == "R-BTC - RSK")
            || (name == "tR-BTC - RSK Testnet");
    }

    function networkHasSegwit(type) {
        var n = network;
        if ("baseNetwork" in network) {
            n = libs.bitcoin.networks[network.baseNetwork];
        }
        // check if only p2wpkh params are required
        if (p2wpkhSelected(type)) {
            return "p2wpkh" in n;
        }
        // check if only p2wpkh-in-p2sh params are required
        else if (p2wpkhInP2shSelected(type)) {
            return "p2wpkhInP2sh" in n;
        }
        // require both if it's unclear which params are required
        return "p2wpkh" in n && "p2wpkhInP2sh" in n;
    }

    function findDerivationPathErrors(path, bip32RootKey) {
        // TODO is not perfect but is better than nothing
        // Inspired by
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
        // and
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#extended-keys
        if (path === undefined || path === null) {
            return "Derivation path undefined"
        }

        var maxDepth = 255; // TODO verify this!!
        var maxIndexValue = Math.pow(2, 31); // TODO verify this!!
        if (path[0] != "m") {
            return "First character must be 'm'";
        }
        if (path.length > 1) {
            if (path[1] != "/") {
                return "Separator must be '/'";
            }
            var indexes = path.split("/");
            if (indexes.length > maxDepth) {
                return "Derivation depth is " + indexes.length + ", must be less than " + maxDepth;
            }
            for (var depth = 1; depth < indexes.length; depth++) {
                var index = indexes[depth];
                var invalidChars = index.replace(/^[0-9]+'?$/g, "")
                if (invalidChars.length > 0) {
                    return "Invalid characters " + invalidChars + " found at depth " + depth;
                }
                var indexValue = parseInt(index.replace("'", ""));
                if (isNaN(depth)) {
                    return "Invalid number at depth " + depth;
                }
                if (indexValue > maxIndexValue) {
                    return "Value of " + indexValue + " at depth " + depth + " must be less than " + maxIndexValue;
                }
            }
        }
        // Check root key exists or else derivation path is useless!
        if (!bip32RootKey) {
            return "No root key";
        }
        // Check no hardened derivation path when using xpub keys
        //var hardenedPath = path.indexOf("'") > -1;
        //var hardenedAddresses = bip32TabSelected() && DOM.hardenedAddresses.prop("checked");
        //var hardened = hardenedPath || hardenedAddresses;
        //var isXpubkey = bip32RootKey.isNeutered();
        //if (hardened && isXpubkey) {
        //    return "Hardened derivation path is invalid with xpub key";
        //}
        return false;
    }

    function derivationPathContainsAccount(type) {
        if (type === "bip44" || type === "bip49" || type === "bip84") {
            return true;
        }
        if (type === "bip32") {
            return `${DOM.bip32path.val()}`.includes("{account}")
        }
        if (type === "bip141") {
            return `${DOM.bip141path.val()}`.includes("{account}")
        }
        return false;
    }

    function getDerivationPath(type, account, change) {
        if (type === "bip44") {
            var derivationPath = `m/44'/${coin}'/${account}'/`;
            if (change !== undefined && change !== null) {
                derivationPath += `${change}`
            }
            console.log("Using derivation path from BIP44 tab: " + derivationPath);
            return derivationPath;
        } else if (type === "bip49") {
            var derivationPath = `m/49'/${coin}'/${account}'/`;
            if (change !== undefined && change !== null) {
                derivationPath += `${change}`
            }
            console.log("Using derivation path from BIP49 tab: " + derivationPath);
            return derivationPath;
        } else if (type === "bip84") {
            var derivationPath = `m/84'/${coin}'/${account}'/`;
            if (change !== undefined && change !== null) {
                derivationPath += `${change}`
            }
            console.log("Using derivation path from BIP84 tab: " + derivationPath);
            return derivationPath;
        } else if (type === "bip32") {
            const derivationPath = DOM.bip32path.val().replace("{account}", `${account}`).replace("{coin}", `${coin}`);
            console.log("Using derivation path from BIP32 tab: " + derivationPath);
            return derivationPath;
        } else if (type === "bip141") {
            const derivationPath = DOM.bip141path.val().replace("{account}", `${account}`).replace("{coin}", `${coin}`);
            console.log("Using derivation path from BIP141 tab: " + derivationPath);
            return derivationPath;
        } else {
            console.log("Unknown derivation path");
            return undefined;
        }
    }

    function calcBip32RootKeyFromSeed(type, phrase, passphrase) {
        const seed = mnemonic.toSeed(phrase, passphrase);
        var bip32RootKey = libs.bitcoin.HDNode.fromSeedHex(seed, getNetwork(type));
        if (isGRS())
            bip32RootKey = libs.groestlcoinjs.HDNode.fromSeedHex(seed, getNetwork(type));
        return [seed, bip32RootKey];
    }

    function segwitSelected(type) {
        return type === "bip49" || type === "bip84" || type === "bip141"
    }

    function p2wpkhSelected(type) {
        return type === "bip84" ||
            type === "bip141" && DOM.bip141semantics.val() == "p2wpkh";
    }

    function p2wpkhInP2shSelected(type) {
        return type === "bip49" ||
            (type === "bip141" && DOM.bip141semantics.val() == "p2wpkh-p2sh");
    }

    function p2wshSelected(type) {
        return type === "bip141" && DOM.bip141semantics.val() == "p2wsh";
    }

    function p2wshInP2shSelected(type) {
        return (type === "bip141" && DOM.bip141semantics.val() == "p2wsh-p2sh");
    }

    function calcBip32ExtendedKey(path, bip32RootKey) {
        // Check there's a root key to derive from
        if (!bip32RootKey) {
            return bip32RootKey;
        }
        var extendedKey = bip32RootKey;
        // Derive the key from the path
        var pathBits = path.split("/");
        for (var i = 0; i < pathBits.length; i++) {
            var bit = pathBits[i];
            var index = parseInt(bit);
            if (isNaN(index)) {
                continue;
            }
            var hardened = bit[bit.length - 1] == "'";
            var isPriv = !(extendedKey.isNeutered());
            var invalidDerivationPath = hardened && !isPriv;
            if (invalidDerivationPath) {
                extendedKey = null;
            } else if (hardened) {
                extendedKey = extendedKey.deriveHardened(index);
            } else {
                extendedKey = extendedKey.derive(index);
            }
        }
        return extendedKey;
    }

    function setHdCoin(coinValue) {
        coin = coinValue;
    }

    function showValidationError(errorText) {
        DOM.feedback
            .text(errorText)
            .show();
    }

    function clearFoundAddressesList() {
        DOM.foundAddresses.empty();
        DOM.foundCsv.val("");
        DOM.numberOfTests.val("0");
        DOM.numberOfHits.val("0");
        updateCsv();
    }

    function clearKeys() {
        clearRootKey();
    }

    function clearRootKey() {
        DOM.rootKey.val("");
    }

    function addAddressToFoundList(passphraseText, indexText, address, pubkey, privkey) {
        var row = $(foundAddressRowTemplate.html());
        // Elements
        var passphraseCell = row.find(".passphrase span");
        var indexCell = row.find(".index span");
        var addressCell = row.find(".address span");
        var pubkeyCell = row.find(".pubkey span");
        var privkeyCell = row.find(".privkey span");
        // Content
        passphraseCell.text(passphraseText);
        indexCell.text(indexText);
        addressCell.text(address);
        pubkeyCell.text(pubkey);
        privkeyCell.text(privkey);
        DOM.foundAddresses.append(row);
        updateCsv();
        //var rowShowQrEls = row.find("[data-show-qr]");
        //setQrEvents(rowShowQrEls);
    }

    function updateCsv() {
        var tableCsv = "passphrase,path,address,public key,private key\n";
        var rows = DOM.foundAddresses.find("tr");
        for (var i = 0; i < rows.length; i++) {
            var row = $(rows[i]);
            var cells = row.find("td");
            for (var j = 0; j < cells.length; j++) {
                var cell = $(cells[j]);
                if (!cell.children().hasClass("invisible")) {
                    tableCsv = tableCsv + cell.text();
                }
                if (j != cells.length - 1) {
                    tableCsv = tableCsv + ",";
                }
            }
            tableCsv = tableCsv + "\n";
        }
        DOM.foundCsv.val(tableCsv);
    }

    function isGRS() {
        return networks[DOM.network.val()].name == "GRS - Groestlcoin" || networks[DOM.network.val()].name == "GRS - Groestlcoin Testnet";
    }

    function isELA() {
        return networks[DOM.network.val()].name == "ELA - Elastos"
    }

    function parseIntNoNaN(val, defaultVal) {
        var v = parseInt(val);
        if (isNaN(v)) {
            return defaultVal;
        }
        return v;
    }

    function showPending() {
        DOM.feedback
            .text("Calculating...")
            .show();
    }

    function showRunningAttack() {
        DOM.feedback
            .text("Running attack...")
            .show();
    }

    function showAttackDone(took) {
        DOM.feedback
            .text("Attack done, took " + took + "ms")
            .show();
    }

    function showStoppedRunningAttack() {
        DOM.feedback
            .text("Attacked stopped")
            .show();
    }

    function findNearestWord(word) {
        var language = getLanguage();
        var words = WORDLISTS[language];
        var minDistance = 99;
        var closestWord = words[0];
        for (var i = 0; i < words.length; i++) {
            var comparedTo = words[i];
            if (comparedTo.indexOf(word) == 0) {
                return comparedTo;
            }
            var distance = libs.levenshtein.get(word, comparedTo);
            if (distance < minDistance) {
                closestWord = comparedTo;
                minDistance = distance;
            }
        }
        return closestWord;
    }

    function hidePending() {
        DOM.feedback
            .text("")
            .hide();
    }

    function hideValidationError() {
        DOM.feedback
            .text("")
            .hide();
    }

    function findPhraseErrors(phrase) {
        // Preprocess the words
        phrase = mnemonic.normalizeString(phrase);
        var words = phraseToWordArray(phrase);
        // Detect blank phrase
        if (words.length == 0) {
            return "Blank mnemonic";
        }
        // Check each word
        for (var i = 0; i < words.length; i++) {
            var word = words[i];
            var language = getLanguage();
            if (WORDLISTS[language].indexOf(word) == -1) {
                console.log("Finding closest match to " + word);
                var nearestWord = findNearestWord(word);
                return word + " not in wordlist, did you mean " + nearestWord + "?";
            }
        }
        // Check the words are valid
        var properPhrase = wordArrayToPhrase(words);
        var isValid = mnemonic.check(properPhrase);
        if (!isValid) {
            return "Invalid mnemonic";
        }
        return false;
    }

    function validateRootKey(type, rootKeyBase58) {
        if (isGRS())
            return validateRootKeyGRS(type, rootKeyBase58);

        // try various segwit network params since this extended key may be from
        // any one of them.
        if (networkHasSegwit(type)) {
            var n = getNetwork(type);
            if ("baseNetwork" in n) {
                n = libs.bitcoin.networks[n.baseNetwork];
            }
            // try parsing using base network params
            try {
                libs.bitcoin.HDNode.fromBase58(rootKeyBase58, n);
                return "";
            } catch (e) {
            }
            // try parsing using p2wpkh params
            if ("p2wpkh" in n) {
                try {
                    libs.bitcoin.HDNode.fromBase58(rootKeyBase58, n.p2wpkh);
                    return "";
                } catch (e) {
                }
            }
            // try parsing using p2wpkh-in-p2sh network params
            if ("p2wpkhInP2sh" in n) {
                try {
                    libs.bitcoin.HDNode.fromBase58(rootKeyBase58, n.p2wpkhInP2sh);
                    return "";
                } catch (e) {
                }
            }
            // try parsing using p2wsh network params
            if ("p2wsh" in n) {
                try {
                    libs.bitcoin.HDNode.fromBase58(rootKeyBase58, n.p2wsh);
                    return "";
                } catch (e) {
                }
            }
            // try parsing using p2wsh-in-p2sh network params
            if ("p2wshInP2sh" in n) {
                try {
                    libs.bitcoin.HDNode.fromBase58(rootKeyBase58, n.p2wshInP2sh);
                    return "";
                } catch (e) {
                }
            }
        }
        // try the network params as currently specified
        try {
            libs.bitcoin.HDNode.fromBase58(rootKeyBase58, getNetwork(type));
        } catch (e) {
            return "Invalid root key";
        }
        return "";
    }

    function validateRootKeyGRS(type, rootKeyBase58) {
        // try various segwit network params since this extended key may be from
        // any one of them.
        if (networkHasSegwit(type)) {
            var n = getNetwork(type);
            if ("baseNetwork" in n) {
                n = libs.bitcoin.networks[n.baseNetwork];
            }
            // try parsing using base network params
            try {
                libs.groestlcoinjs.HDNode.fromBase58(rootKeyBase58, n);
                return "";
            } catch (e) {
            }
            // try parsing using p2wpkh params
            if ("p2wpkh" in n) {
                try {
                    libs.groestlcoinjs.HDNode.fromBase58(rootKeyBase58, n.p2wpkh);
                    return "";
                } catch (e) {
                }
            }
            // try parsing using p2wpkh-in-p2sh network params
            if ("p2wpkhInP2sh" in n) {
                try {
                    libs.groestlcoinjs.HDNode.fromBase58(rootKeyBase58, n.p2wpkhInP2sh);
                    return "";
                } catch (e) {
                }
            }
        }
        // try the network params as currently specified
        try {
            libs.groestlcoinjs.HDNode.fromBase58(rootKeyBase58, getNetwork(type));
        } catch (e) {
            return "Invalid root key";
        }
        return "";
    }

    function populateNetworkSelect() {
        for (var i = 0; i < networks.length; i++) {
            var network = networks[i];
            var option = $("<option>");
            option.attr("value", i);
            option.text(network.name);
            if (network.name == "BTC - Bitcoin") {
                option.prop("selected", true);
            }
            DOM.phraseNetwork.append(option);
        }
        DOM.blockBookUrl.val("https://btc1.trezor.io")
    }

    function populateClientSelect() {
        for (var i = 0; i < clients.length; i++) {
            var client = clients[i];
            var option = $("<option>");
            option.attr("value", i);
            option.text(client.name);
            DOM.bip32Client.append(option);
        }
    }

    function getLanguage() {
        var defaultLanguage = "english";
        // Try to get from existing phrase
        var language = getLanguageFromPhrase();
        // Try to get from url if not from phrase
        if (language.length == 0) {
            language = getLanguageFromUrl();
        }
        // Default to English if no other option
        if (language.length == 0) {
            language = defaultLanguage;
        }
        return language;
    }

    function getLanguageFromPhrase(phrase) {
        // Check if how many words from existing phrase match a language.
        var language = "";
        if (!phrase) {
            phrase = DOM.phrase.val();
        }
        if (phrase.length > 0) {
            var words = phraseToWordArray(phrase);
            var languageMatches = {};
            for (l in WORDLISTS) {
                // Track how many words match in this language
                languageMatches[l] = 0;
                for (var i = 0; i < words.length; i++) {
                    var wordInLanguage = WORDLISTS[l].indexOf(words[i]) > -1;
                    if (wordInLanguage) {
                        languageMatches[l]++;
                    }
                }
                // Find languages with most word matches.
                // This is made difficult due to commonalities between Chinese
                // simplified vs traditional.
                var mostMatches = 0;
                var mostMatchedLanguages = [];
                for (var l in languageMatches) {
                    var numMatches = languageMatches[l];
                    if (numMatches > mostMatches) {
                        mostMatches = numMatches;
                        mostMatchedLanguages = [l];
                    } else if (numMatches == mostMatches) {
                        mostMatchedLanguages.push(l);
                    }
                }
            }
            if (mostMatchedLanguages.length > 0) {
                // Use first language and warn if multiple detected
                language = mostMatchedLanguages[0];
                if (mostMatchedLanguages.length > 1) {
                    console.warn("Multiple possible languages");
                    console.warn(mostMatchedLanguages);
                }
            }
        }
        return language;
    }

    function getLanguageFromUrl() {
        for (var language in WORDLISTS) {
            if (window.location.hash.indexOf(language) > -1) {
                return language;
            }
        }
        return "";
    }

    function setMnemonicLanguage() {
        var language = getLanguage();
        // Load the bip39 mnemonic generator for this language if required
        if (!(language in mnemonics)) {
            mnemonics[language] = new Mnemonic(language);
        }
        mnemonic = mnemonics[language];
    }

    function convertPhraseToNewLanguage() {
        var oldLanguage = getLanguageFromPhrase();
        var newLanguage = getLanguageFromUrl();
        var oldPhrase = DOM.phrase.val();
        var oldWords = phraseToWordArray(oldPhrase);
        var newWords = [];
        for (var i = 0; i < oldWords.length; i++) {
            var oldWord = oldWords[i];
            var index = WORDLISTS[oldLanguage].indexOf(oldWord);
            var newWord = WORDLISTS[newLanguage][index];
            newWords.push(newWord);
        }
        newPhrase = wordArrayToPhrase(newWords);
        return newPhrase;
    }

    // TODO look at jsbip39 - mnemonic.splitWords
    function phraseToWordArray(phrase) {
        var words = phrase.split(/\s/g);
        var noBlanks = [];
        for (var i = 0; i < words.length; i++) {
            var word = words[i];
            if (word.length > 0) {
                noBlanks.push(word);
            }
        }
        return noBlanks;
    }

    // TODO look at jsbip39 - mnemonic.joinWords
    function wordArrayToPhrase(words) {
        var phrase = words.join(" ");
        var language = getLanguageFromPhrase(phrase);
        if (language == "japanese") {
            phrase = words.join("\u3000");
        }
        return phrase;
    }

    function getNetwork(type) {
        var currentNetwork = network
        if ("baseNetwork" in currentNetwork) {
            currentNetwork = libs.bitcoin.networks[currentNetwork.baseNetwork];
        }
        // choose the right segwit params
        if (p2wpkhSelected(type) && "p2wpkh" in currentNetwork) {
            currentNetwork = currentNetwork.p2wpkh;
        } else if (p2wpkhInP2shSelected(type) && "p2wpkhInP2sh" in currentNetwork) {
            currentNetwork = currentNetwork.p2wpkhInP2sh;
        } else if (p2wshSelected(type) && "p2wsh" in currentNetwork) {
            currentNetwork = currentNetwork.p2wsh;
        } else if (p2wshInP2shSelected(type) && "p2wshInP2sh" in currentNetwork) {
            currentNetwork = currentNetwork.p2wshInP2sh;
        }
        return currentNetwork
    }

    var networks = [
        {
            name: "AC - Asiacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.asiacoin;
                setHdCoin(51);
            },
        },
        {
            name: "ACC - Adcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.adcoin;
                setHdCoin(161);
            },
        },
        {
            name: "AGM - Argoneum",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.argoneum;
                setHdCoin(421);
            },
        },
        {
            name: "ARYA - Aryacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.aryacoin;
                setHdCoin(357);
            },
        },
        {
            name: "ATOM - Cosmos Hub",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(118);
            },
        },
        {
            name: "AUR - Auroracoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.auroracoin;
                setHdCoin(85);
            },
        },
        {
            name: "AXE - Axe",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.axe;
                setHdCoin(4242);
            },
        },
        {
            name: "ANON - ANON",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.anon;
                setHdCoin(220);
            },
        },
        {
            name: "BOLI - Bolivarcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bolivarcoin;
                setHdCoin(278);
            },
        },
        {
            name: "BCA - Bitcoin Atom",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.atom;
                setHdCoin(185);
            },
        },
        {
            name: "BCH - Bitcoin Cash",
            blockBookAddress: "https://bch1.trezor.io",
            onSelect: function () {
                DOM.bitcoinCashAddressTypeContainer.removeClass("hidden");
                setHdCoin(145);
            },
        },
        {
            name: "BEET - Beetlecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.beetlecoin;
                setHdCoin(800);
            },
        },
        {
            name: "BELA - Belacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.belacoin;
                setHdCoin(73);
            },
        },
        {
            name: "BLK - BlackCoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.blackcoin;
                setHdCoin(10);
            },
        },
        {
            name: "BND - Blocknode",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.blocknode;
                setHdCoin(2941);
            },
        },
        {
            name: "tBND - Blocknode Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.blocknode_testnet;
                setHdCoin(1);
            },
        },
        {
            name: "BRIT - Britcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.britcoin;
                setHdCoin(70);
            },
        },
        {
            name: "BSD - Bitsend",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitsend;
                setHdCoin(91);
            },
        },
        {
            name: "BST - BlockStamp",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.blockstamp;
                setHdCoin(254);
            },
        },
        {
            name: "BTA - Bata",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bata;
                setHdCoin(89);
            },
        },
        {
            name: "BTC - Bitcoin",
            blockBookAddress: "https://btc1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(0);
            },
        },
        {
            name: "BTC - Bitcoin RegTest",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.regtest;
                // Using hd coin value 1 based on bip44_coin_type
                // https://github.com/chaintope/bitcoinrb/blob/f1014406f6b8f9b4edcecedc18df70c80df06f11/lib/bitcoin/chainparams/regtest.yml
                setHdCoin(1);
            },
        },
        {
            name: "BTC - Bitcoin Testnet",
            blockBookAddress: "https://tbtc1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.testnet;
                setHdCoin(1);
            },
        },
        {
            name: "BITG - Bitcoin Green",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoingreen;
                setHdCoin(222);
            },
        },
        {
            name: "BTCP - Bitcoin Private",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoinprivate;
                setHdCoin(183);
            },
        },
        {
            name: "BTCPt - Bitcoin Private Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoinprivatetestnet;
                setHdCoin(1);
            },
        },
        {
            name: "BSC - Binance Smart Chain",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(60);
            },
        },
        {
            name: "BSV - BitcoinSV",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoinsv;
                setHdCoin(236);
            },
        },
        {
            name: "BTCZ - Bitcoinz",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoinz;
                setHdCoin(177);
            },
        },
        {
            name: "BTDX - BitCloud",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcloud;
                setHdCoin(218);
            },
        },
        {
            name: "BTG - Bitcoin Gold",
            blockBookAddress: "https://btg1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.bgold;
                setHdCoin(156);
            },
        },
        {
            name: "BTX - Bitcore",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcore;
                setHdCoin(160);
            },
        },
        {
            name: "CCN - Cannacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.cannacoin;
                setHdCoin(19);
            },
        },
        {
            name: "CESC - Cryptoescudo",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.cannacoin;
                setHdCoin(111);
            },
        },
        {
            name: "CDN - Canadaecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.canadaecoin;
                setHdCoin(34);
            },
        },
        {
            name: "CLAM - Clams",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.clam;
                setHdCoin(23);
            },
        },
        {
            name: "CLO - Callisto",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(820);
            },
        },
        {
            name: "CLUB - Clubcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.clubcoin;
                setHdCoin(79);
            },
        },
        {
            name: "CMP - Compcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.compcoin;
                setHdCoin(71);
            },
        },
        {
            name: "CPU - CPUchain",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.cpuchain;
                setHdCoin(363);
            },
        },
        {
            name: "CRAVE - Crave",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.crave;
                setHdCoin(186);
            },
        },
        {
            name: "CRP - CranePay",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.cranepay;
                setHdCoin(2304);
            },
        },

        {
            name: "CRW - Crown (Legacy)",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.crown;
                setHdCoin(72);
            },
        },
        {
            name: "CRW - Crown",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.crown;
                setHdCoin(72);
            },
        },
        {
            name: "CSC - CasinoCoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(359);
            },
        },
        {
            name: "DASH - Dash",
            blockBookAddress: "https://dash1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.dash;
                setHdCoin(5);
            },
        },
        {
            name: "DASH - Dash Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.dashtn;
                setHdCoin(1);
            },
        },
        {
            name: "DFC - Defcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.defcoin;
                setHdCoin(1337);
            },
        },
        {
            name: "DGB - Digibyte",
            blockBookAddress: "https://dgb1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.digibyte;
                setHdCoin(20);
            },
        },
        {
            name: "DGC - Digitalcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.digitalcoin;
                setHdCoin(18);
            },
        },
        {
            name: "DIVI - DIVI",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.divi;
                setHdCoin(301);
            },
        },
        {
            name: "DIVI - DIVI Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.divitestnet;
                setHdCoin(1);
            },
        },
        {
            name: "DMD - Diamond",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.diamond;
                setHdCoin(152);
            },
        },
        {
            name: "DNR - Denarius",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.denarius;
                setHdCoin(116);
            },
        },
        {
            name: "DOGE - Dogecoin",
            blockBookAddress: "https://doge1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.dogecoin;
                setHdCoin(3);
            },
        },
        {
            name: "DOGEt - Dogecoin Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.dogecointestnet;
                setHdCoin(1);
            },
        },
        {
            name: "DXN - DEXON",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(237);
            },
        },
        {
            name: "ECN - Ecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.ecoin;
                setHdCoin(115);
            },
        },
        {
            name: "EDRC - Edrcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.edrcoin;
                setHdCoin(56);
            },
        },
        {
            name: "EFL - Egulden",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.egulden;
                setHdCoin(78);
            },
        },
        {
            name: "ELA - Elastos",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.elastos;
                setHdCoin(2305);
            },
        },
        {
            name: "ELLA - Ellaism",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(163);
            },
        },
        {
            name: "EMC2 - Einsteinium",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.einsteinium;
                setHdCoin(41);
            },
        },
        {
            name: "ERC - Europecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.europecoin;
                setHdCoin(151);
            },
        },
        {
            name: "EOS - EOSIO",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(194);
            },
        },
        {
            name: "ERE - EtherCore",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(466);
            },
        },
        {
            name: "ESN - Ethersocial Network",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(31102);
            },
        },
        {
            name: "ETC - Ethereum Classic",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(61);
            },
        },
        {
            name: "ETH - Ethereum",
            blockBookAddress: "https://eth1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(60);
            },
        },
        {
            name: "EWT - EnergyWeb",
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(246);
            },
        },
        {
            name: "EXCL - Exclusivecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.exclusivecoin;
                setHdCoin(190);
            },
        },
        {
            name: "EXCC - ExchangeCoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.exchangecoin;
                setHdCoin(0);
            },
        },
        {
            name: "EXP - Expanse",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(40);
            },
        },
        {
            name: "FIO - Foundation for Interwallet Operability",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(235);
            },
        },
        {
            name: "FIRO - Firo (Zcoin rebrand)",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.firo;
                setHdCoin(136);
            },
        },
        {
            name: "FIX - FIX",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.fix;
                setHdCoin(336);
            },
        },
        {
            name: "FIX - FIX Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.fixtestnet;
                setHdCoin(1);
            },
        },
        {
            name: "FJC - Fujicoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.fujicoin;
                setHdCoin(75);
            },
        },
        {
            name: "FLASH - Flashcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.flashcoin;
                setHdCoin(120);
            },
        },
        {
            name: "FRST - Firstcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.firstcoin;
                setHdCoin(167);
            },
        },
        {
            name: "FTC - Feathercoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.feathercoin;
                setHdCoin(8);
            },
        },
        {
            name: "GAME - GameCredits",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.game;
                setHdCoin(101);
            },
        },
        {
            name: "GBX - Gobyte",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.gobyte;
                setHdCoin(176);
            },
        },
        {
            name: "GCR - GCRCoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.gcr;
                setHdCoin(79);
            },
        },
        {
            name: "GRC - Gridcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.gridcoin;
                setHdCoin(84);
            },
        },
        {
            name: "GRS - Groestlcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.groestlcoin;
                setHdCoin(17);
            },
        },
        {
            name: "GRS - Groestlcoin Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.groestlcointestnet;
                setHdCoin(1);
            },
        },
        {
            name: "HNS - Handshake",
            blockBookAddress: undefined,
            onSelect: function () {
                setHdCoin(5353);
            },
        },
        {
            name: "HNC - Helleniccoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.helleniccoin;
                setHdCoin(168);
            },
        },
        {
            name: "HUSH - Hush (Legacy)",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.hush;
                setHdCoin(197);
            },
        },
        {
            name: "HUSH - Hush3",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.hush3;
                setHdCoin(197);
            },
        },
        {
            name: "INSN - Insane",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.insane;
                setHdCoin(68);
            },
        },
        {
            name: "IOP - Iop",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.iop;
                setHdCoin(66);
            },
        },
        {
            name: "IOV - Starname",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(234);
            },
        },
        {
            name: "IXC - Ixcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.ixcoin;
                setHdCoin(86);
            },
        },
        {
            name: "JBS - Jumbucks",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.jumbucks;
                setHdCoin(26);
            },
        },
        {
            name: "KMD - Komodo",
            blockBookAddress: undefined,
            bip49available: false,
            onSelect: function () {
                network = libs.bitcoin.networks.komodo;
                setHdCoin(141);
            },
        },
        {
            name: "KOBO - Kobocoin",
            blockBookAddress: undefined,
            bip49available: false,
            onSelect: function () {
                network = libs.bitcoin.networks.kobocoin;
                setHdCoin(196);
            },
        },
        {
            name: "LBC - Library Credits",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.lbry;
                setHdCoin(140);
            },
        },
        {
            name: "LCC - Litecoincash",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.litecoincash;
                setHdCoin(192);
            },
        },
        {
            name: "LDCN - Landcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.landcoin;
                setHdCoin(63);
            },
        },
        {
            name: "LINX - Linx",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.linx;
                setHdCoin(114);
            },
        },
        {
            name: "LKR - Lkrcoin",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.lkrcoin;
                setHdCoin(557);
            },
        },
        {
            name: "LTC - Litecoin",
            blockBookAddress: "https://ltc1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.litecoin;
                setHdCoin(2);
                DOM.litecoinLtubContainer.removeClass("hidden");
            },
        },
        {
            name: "LTCt - Litecoin Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.litecointestnet;
                setHdCoin(1);
                DOM.litecoinLtubContainer.removeClass("hidden");
            },
        },
        {
            name: "LTZ - LitecoinZ",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.litecoinz;
                setHdCoin(221);
            },
        },
        {
            name: "LUNA - Terra",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(330);
            },
        },
        {
            name: "LYNX - Lynx",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.lynx;
                setHdCoin(191);
            },
        },
        {
            name: "MAZA - Maza",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.maza;
                setHdCoin(13);
            },
        },
        {
            name: "MEC - Megacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.megacoin;
                setHdCoin(217);
            },
        },
        {
            name: "MIX - MIX",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(76);
            },
        },
        {
            name: "MNX - Minexcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.minexcoin;
                setHdCoin(182);
            },
        },
        {
            name: "MONA - Monacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.monacoin,
                    setHdCoin(22);
            },
        },
        {
            name: "MONK - Monkey Project",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.monkeyproject,
                    setHdCoin(214);
            },
        },
        {
            name: "MOAC - MOAC",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(314);
            },
        },
        {
            name: "MUSIC - Musicoin",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(184);
            },
        },
        {
            name: "NANO - Nano",
            blockBookAddress: undefined,
            onSelect: function () {
                network = network = libs.nanoUtil.dummyNetwork;
                setHdCoin(165);
            },
        },
        {
            name: "NAV - Navcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.navcoin;
                setHdCoin(130);
            },
        },
        {
            name: "NAS - Nebulas",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(2718);
            },
        },
        {
            name: "NEBL - Neblio",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.neblio;
                setHdCoin(146);
            },
        },
        {
            name: "NEOS - Neoscoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.neoscoin;
                setHdCoin(25);
            },
        },
        {
            name: "NIX - NIX Platform",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.nix;
                setHdCoin(400);
            },
        },
        {
            name: "NLG - Gulden",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.gulden;
                setHdCoin(87);
            },
        },
        {
            name: "NMC - Namecoin",
            blockBookAddress: "https://nmc1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.namecoin;
                setHdCoin(7);
            },
        },
        {
            name: "NRG - Energi",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.energi;
                setHdCoin(204);
            },
        },
        {
            name: "NRO - Neurocoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.neurocoin;
                setHdCoin(110);
            },
        },
        {
            name: "NSR - Nushares",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.nushares;
                setHdCoin(11);
            },
        },
        {
            name: "NYC - Newyorkc",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.newyorkc;
                setHdCoin(179);
            },
        },
        {
            name: "NVC - Novacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.novacoin;
                setHdCoin(50);
            },
        },
        {
            name: "OK - Okcash",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.okcash;
                setHdCoin(69);
            },
        },
        {
            name: "OMNI - Omnicore",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.omnicore;
                setHdCoin(200);
            },
        },
        {
            name: "ONION - DeepOnion",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.deeponion;
                setHdCoin(305);
            },
        },
        {
            name: "ONX - Onixcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.onixcoin;
                setHdCoin(174);
            },
        },
        {
            name: "PART - Particl",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.particl;
                setHdCoin(44);
            },
        },
        {
            name: "PHR - Phore",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.phore;
                setHdCoin(444);
            },
        },
        {
            name: "PINK - Pinkcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.pinkcoin;
                setHdCoin(117);
            },
        },
        {
            name: "PIRL - Pirl",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(164);
            },
        },
        {
            name: "PIVX - PIVX",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.pivx;
                setHdCoin(119);
            },
        },
        {
            name: "PIVX - PIVX Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.pivxtestnet;
                setHdCoin(1);
            },
        },
        {
            name: "POA - Poa",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(178);
            },
        },
        {
            name: "POSW - POSWcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.poswcoin;
                setHdCoin(47);
            },
        },
        {
            name: "POT - Potcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.potcoin;
                setHdCoin(81);
            },
        },
        {
            name: "PPC - Peercoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.peercoin;
                setHdCoin(6);
            },
        },
        {
            name: "PRJ - ProjectCoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.projectcoin;
                setHdCoin(533);
            },
        },
        {
            name: "PSB - Pesobit",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.pesobit;
                setHdCoin(62);
            },
        },
        {
            name: "PUT - Putincoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.putincoin;
                setHdCoin(122);
            },
        },
        {
            name: "RPD - Rapids",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.rapids;
                setHdCoin(320);
            },
        },
        {
            name: "RVN - Ravencoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.ravencoin;
                setHdCoin(175);
            },
        },
        {
            name: "R-BTC - RSK",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.rsk;
                setHdCoin(137);
            },
        },
        {
            name: "tR-BTC - RSK Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.rsktestnet;
                setHdCoin(37310);
            },
        },
        {
            name: "RBY - Rubycoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.rubycoin;
                setHdCoin(16);
            },
        },
        {
            name: "RDD - Reddcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.reddcoin;
                setHdCoin(4);
            },
        },
        {
            name: "RITO - Ritocoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.ritocoin;
                setHdCoin(19169);
            },
        },
        {
            name: "RUNE - THORChain",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(931);
            },
        },
        {
            name: "RVR - RevolutionVR",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.revolutionvr;
                setHdCoin(129);
            },
        },
        {
            name: "SAFE - Safecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.safecoin;
                setHdCoin(19165);
            },
        },
        {
            name: "SCRIBE - Scribe",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.scribe;
                setHdCoin(545);
            },
        },
        {
            name: "SLS - Salus",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.salus;
                setHdCoin(63);
            },
        },
        {
            name: "SDC - ShadowCash",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.shadow;
                setHdCoin(35);
            },
        },
        {
            name: "SDC - ShadowCash Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.shadowtn;
                setHdCoin(1);
            },
        },
        {
            name: "SLM - Slimcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.slimcoin;
                setHdCoin(63);
            },
        },
        {
            name: "SLM - Slimcoin Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.slimcointn;
                setHdCoin(111);
            },
        },
        {
            name: "SLP - Simple Ledger Protocol",
            blockBookAddress: undefined,
            onSelect: function () {
                DOM.bitcoinCashAddressTypeContainer.removeClass("hidden");
                setHdCoin(245);
            },
        },
        {
            name: "SLR - Solarcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.solarcoin;
                setHdCoin(58);
            },
        },
        {
            name: "SMLY - Smileycoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.smileycoin;
                setHdCoin(59);
            },
        },
        {
            name: "STASH - Stash",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.stash;
                setHdCoin(0xC0C0);
            },
        },
        {
            name: "STASH - Stash Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.stashtn;
                setHdCoin(0xCAFE);
            },
        },
        {
            name: "STRAT - Stratis",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.stratis;
                setHdCoin(105);
            },
        },
        {
            name: "SUGAR - Sugarchain",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.sugarchain;
                setHdCoin(408);
            },
        },
        {
            name: "TUGAR - Sugarchain Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.sugarchaintestnet;
                setHdCoin(408);
            },
        },
        {
            name: "SWTC - Jingtum",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(315);
            },
        },
        {
            name: "TSTRAT - Stratis Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.stratistest;
                setHdCoin(105);
            },
        },
        {
            name: "SYS - Syscoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.syscoin;
                setHdCoin(57);
            },
        },
        {
            name: "THC - Hempcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.hempcoin;
                setHdCoin(113);
            },
        },
        {
            name: "THT - Thought",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.thought;
                setHdCoin(1618);
            },
        },
        {
            name: "TOA - Toa",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.toa;
                setHdCoin(159);
            },
        },
        {
            name: "TRX - Tron",
            blockBookAddress: undefined,
            onSelect: function () {
                setHdCoin(195);
            },
        },
        {
            name: "TWINS - TWINS",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.twins;
                setHdCoin(970);
            },
        },
        {
            name: "TWINS - TWINS Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.twinstestnet;
                setHdCoin(1);
            },
        },
        {
            name: "USC - Ultimatesecurecash",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.ultimatesecurecash;
                setHdCoin(112);
            },
        },
        {
            name: "USNBT - NuBits",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.nubits;
                setHdCoin(12);
            },
        },
        {
            name: "UNO - Unobtanium",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.unobtanium;
                setHdCoin(92);
            },
        },
        {
            name: "VASH - Vpncoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.vpncoin;
                setHdCoin(33);
            },
        },
        {
            name: "VET - VeChain",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(818);
            },
        },
        {
            name: "VIA - Viacoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.viacoin;
                setHdCoin(14);
            },
        },
        {
            name: "VIA - Viacoin Testnet",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.viacointestnet;
                setHdCoin(1);
            },
        },
        {
            name: "VIVO - Vivo",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.vivo;
                setHdCoin(166);
            },
        },
        {
            name: "VTC - Vertcoin",
            blockBookAddress: "https://vtc1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.vertcoin;
                setHdCoin(28);
            },
        },
        {
            name: "WGR - Wagerr",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.wagerr;
                setHdCoin(7825266);
            },
        },
        {
            name: "WC - Wincoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.wincoin;
                setHdCoin(181);
            },
        },
        {
            name: "XAX - Artax",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.artax;
                setHdCoin(219);
            },
        },
        {
            name: "XBC - Bitcoinplus",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoinplus;
                setHdCoin(65);
            },
        },
        {
            name: "XLM - Stellar",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.stellarUtil.dummyNetwork;
                setHdCoin(148);
            },
        },
        {
            name: "XMY - Myriadcoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.myriadcoin;
                setHdCoin(90);
            },
        },
        {
            name: "XRP - Ripple",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(144);
            },
        },
        {
            name: "XVC - Vcash",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.vcash;
                setHdCoin(127);
            },
        },
        {
            name: "XVG - Verge",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.verge;
                setHdCoin(77);
            },
        },
        {
            name: "XUEZ - Xuez",
            blockBookAddress: undefined,
            segwitAvailable: false,
            onSelect: function () {
                network = libs.bitcoin.networks.xuez;
                setHdCoin(225);
            },
        },
        {
            name: "XWCC - Whitecoin Classic",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.whitecoin;
                setHdCoin(155);
            },
        },
        {
            name: "XZC - Zcoin (rebranded to Firo)",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.zcoin;
                setHdCoin(136);
            },
        },
        {
            name: "ZBC - ZooBlockchain",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.zoobc;
                setHdCoin(883);
            },
        },
        {
            name: "ZCL - Zclassic",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.zclassic;
                setHdCoin(147);
            },
        },
        {
            name: "ZEC - Zcash",
            blockBookAddress: "https://zec1.trezor.io",
            onSelect: function () {
                network = libs.bitcoin.networks.zcash;
                setHdCoin(133);
            },
        },
        {
            name: "ZEN - Horizen",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.zencash;
                setHdCoin(121);
            },
        },
        {
            name: "XWC - Whitecoin",
            blockBookAddress: undefined,
            onSelect: function () {
                network = libs.bitcoin.networks.bitcoin;
                setHdCoin(559);
            },
        }
    ]

    var clients = [
        {
            name: "Bitcoin Core",
            onSelect: function () {
                DOM.bip32path.val("m/0'/0'");
                //DOM.hardenedAddresses.prop('checked', true);
            },
        },
        {
            name: "blockchain.info",
            onSelect: function () {
                DOM.bip32path.val("m/44'/0'/0'");
                //DOM.hardenedAddresses.prop('checked', false);
            },
        },
        {
            name: "MultiBit HD",
            onSelect: function () {
                DOM.bip32path.val("m/0'/0");
                //DOM.hardenedAddresses.prop('checked', false);
            },
        },
        {
            name: "Coinomi, Ledger",
            onSelect: function () {
                DOM.bip32path.val("m/44'/" + DOM.bip44coin.val() + "'/0'");
                //DOM.hardenedAddresses.prop('checked', false);
            },
        }
    ]

    function toChecksumAddressForRsk(address, chainId = null) {
        if (typeof address !== "string") {
            throw new Error("address parameter should be a string.");
        }

        if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) {
            throw new Error("Given address is not a valid RSK address: " + address);
        }

        var stripAddress = stripHexPrefix(address).toLowerCase();
        var prefix = chainId != null ? chainId.toString() + "0x" : "";
        var keccakHash = libs.ethUtil.keccak256(prefix + stripAddress)
            .toString("hex")
            .replace(/^0x/i, "");
        var checksumAddress = "0x";

        for (var i = 0; i < stripAddress.length; i++) {
            checksumAddress +=
                parseInt(keccakHash[i], 16) >= 8 ?
                    stripAddress[i].toUpperCase() :
                    stripAddress[i];
        }

        return checksumAddress;
    }

    function calcAddressForELA(seed, coin, account, change, index) {
        if (!isELA()) {
            return;
        }

        const publicKey = libs.elastosjs.getDerivedPublicKey(libs.elastosjs.getMasterPublicKey(seed), change, index);
        return {
            privateKey: libs.elastosjs.getDerivedPrivateKey(seed, coin, account, change, index),
            publicKey: publicKey,
            address: libs.elastosjs.getAddress(publicKey.toString('hex'))
        };
    }

    function disableForms() {
        $("form").on("submit", function (e) {
            e.preventDefault();
        });
    }

    init();

})();
