package net.corda.core.contracts

import net.corda.core.crypto.Party
import net.corda.core.crypto.composite
import net.corda.core.crypto.generateKeyPair
import net.corda.core.hours
import net.corda.core.serialization.serialize
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.OpReturnApi
import org.junit.Test
import java.security.KeyPair
import java.time.Instant

/**
 * Created by James Sangalli on 23/01/2017.
 */
class btcFundTraderTest {

    val testContract = btcFundTrader()

    @Test
    fun getLegalContractReference()
    {
        println(testContract.legalContractReference)
    }

    @Test
    fun transferFunds()
    {
        //if transaction is successfully generated than the verify function call was successful
        //owner state transaction
        val BTCFUND : KeyPair = generateKeyPair()
        val notary : KeyPair = generateKeyPair()
        val owner : KeyPair = generateKeyPair()
        val newOwner : KeyPair = generateKeyPair()

        val id : String = "http://compliancewiki.lifewireless.com/images/c/c9/Ne_sample_id_09.jpg"
        //provide the url to an id
        val btcAddr : String = "3Nxwenay9Z8Lc9JBiywExpnEFiLp6Afp8v"
        val notaryParty : Party = Party("APCA", notary.public)
        val fundParty : Party = Party("BTCFUND", BTCFUND.public)

        val state = btcFundTrader.State("BTC", 1200, 10, notaryParty, fundParty, notary.public.composite, btcAddr, id)

        println(state)

        println("\n the notary to the transaction is: "
                + testContract.generateTransaction(state).notary)

        val issuance: SignedTransaction = run {
            val tx = testContract.generateTransaction(state)

            tx.setTime(Instant.now(), (24 * 7).hours) //valid for 1 week

            tx.signWith(notary)
            tx.signWith(owner)
            tx.signWith(BTCFUND)
            //tx.addAttachment(SecureHash.sha256(id)) //hashes the photo id and adds it as an attachment
            val stx = tx.toSignedTransaction(true)

            println(stx)
            val signedTxHash = stx.serialize().hash.toString()
            //stores signed transaction hash on bitcoin testnet OP_RETURN
            //Useful for high priority transactions
            OpReturnApi.storeTxHashOnBlockchain(signedTxHash)

            stx
        }

        val trade: SignedTransaction = run {
            val builder = TransactionType.General.Builder(notaryParty)
            //CBA-JamesB: move to user public key
            btcFundTrader().transferFunds(builder, issuance.tx.outRef(0), newOwner.public.composite)
            builder.signWith(owner)
            builder.signWith(notary)
            val tx = builder.toSignedTransaction(true)
            OpReturnApi.storeTxHashOnBlockchain(tx.serialize().hash.toString())
            tx
        }

    }

}