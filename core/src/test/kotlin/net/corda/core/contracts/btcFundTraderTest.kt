package net.corda.core.contracts

import net.corda.core.crypto.CompositeKey
import net.corda.core.crypto.Party
import net.corda.core.crypto.composite
import net.corda.core.crypto.generateKeyPair
import net.corda.core.hours
import net.corda.core.transactions.SignedTransaction
import org.junit.Test
import java.security.KeyPair
import java.time.Instant
import com.github.kittinunf.fuel.Fuel
import net.corda.core.serialization.serialize

/**
 * Created by James Sangalli on 23/01/2017.
 */
class btcFundTraderTest {

    val testContract = btcFundTrader()

    fun storeTxHashOnBlockchain(txHash: String)
    {
        println("Hash to be stored on blockchain: " + txHash)
        //view the transactions on: http://tbtc.blockr.io/address/info/mnoQEPQe1D7hy2mvByJZk7cQ2JCd64cawA
        Fuel.post("https://op-return.herokuapp.com/v2/saveTxHashInBlockchain/" + txHash)
        .response{ request, response, result ->
            println("response: " + response)
            println("result: " + result)
            println("request: " + request)
        }
    }

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
            storeTxHashOnBlockchain(signedTxHash) //stores signed transaction hash on bitcoin testnet OP_RETURN

            stx
        }

        val requiredKeys:List<CompositeKey> = arrayListOf(owner.public.composite,
                notary.public.composite, BTCFUND.public.composite)

        val trade: SignedTransaction = run {
            val builder = TransactionType.General.Builder(notaryParty)
            //CBA-JamesB: move to user public key
            btcFundTrader().transferFunds(builder, issuance.tx.outRef(0), newOwner.public.composite)
            builder.signWith(owner)
            builder.signWith(notary)
            val tx = builder.toSignedTransaction(true)
            tx
        }

    }

}