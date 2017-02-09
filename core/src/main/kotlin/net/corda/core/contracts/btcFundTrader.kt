package net.corda.core.contracts

import net.corda.core.contracts.clauses.GroupClauseVerifier
import net.corda.core.crypto.CompositeKey
import net.corda.core.crypto.Party
import net.corda.core.crypto.SecureHash
import net.corda.core.schemas.MappedSchema
import net.corda.core.schemas.PersistentState
import net.corda.core.schemas.QueryableState
import net.corda.core.schemas.btcFundTraderSchema
import net.corda.core.transactions.TransactionBuilder
import java.security.PublicKey
import java.time.Instant

/**
 * Created by sangalli on 23/01/2017, adapted from CommercialPaper.kt.
 */

class btcFundTrader : Contract
{
    data class State(
            val currencySymbol: String = "BTC",
            val currentPrice: Int,
            val amount: Int,
            val notary: Party,
            val issuer: Party,
            override val owner: CompositeKey,
            val bitcoinAddress: String,
            val idImageURL: String
    ): OwnableState, QueryableState, BitcoinOwnershipInformation {
        override val dealerMasterKey = bitcoinAddress
        override val identification = idImageURL
        override val contract = btcFundTrader()
        override val participants: List<CompositeKey>
            get() = listOf(owner)
        override fun withNewOwner(newOwner: CompositeKey) =
                Pair(Commands.Move(), copy(owner = newOwner))
        /** Object Relational Mapping support. */
        override fun supportedSchemas(): Iterable<MappedSchema> = listOf(btcFundTraderSchema)
        /** Object Relational Mapping support. */
        override fun generateMappedObject(schema: MappedSchema): PersistentState {
            return when (schema) {
                is btcFundTraderSchema -> btcFundTraderSchema.PersistentBtcFundTraderSchema(
                        currencySymbol = currencySymbol,
                        currentPrice = 1200,
                        issuer = issuer,
                        notary = notary,
                        owner = owner,
                        amount = amount,
                        id = idImageURL,
                        bitcoinAddress = bitcoinAddress
                )
                else -> throw IllegalArgumentException("Unrecognised schema $schema")
            }
        }
    }


    override val legalContractReference: SecureHash = SecureHash.sha256("BTCFUND trade commencing on: "
            + Instant.now())

//    override fun verify(transaction: TransactionForContract) {
//        verifyClause(transaction, Clauses.Group(),
//                transaction.commands.select<Commands>())
//    }

    override fun verify(tx: TransactionForContract) {
        // Always accepts.
    }

    fun generateTransaction(state : State) : TransactionBuilder
    {
        val tx = TransactionType.General.Builder(notary = state.notary).withItems(state,
                Command(btcFundTrader.Commands.Move(), state.issuer.owningKey))
        tx.addCommand(btcFundTrader.Commands.issueFunds(), state.issuer.owningKey)
        return tx
    }

    /**
     * Updates the given partial transaction with an input/output/command to reassign ownership.
     */
    fun transferFunds (tx: TransactionBuilder, paper: StateAndRef<btcFundTrader.State>, newOwner: CompositeKey)
                       //,requiredKeys:List<CompositeKey>)
            : TransactionBuilder
    {
        tx.addInputState(paper)
        tx.addOutputState(TransactionState(paper.state.data.copy(owner = newOwner), paper.state.notary))
        //tx.addCommand(btcFundTrader.Commands.Move(), paper.state.data.owner)
        //tx.addCommand(data = btcFundTrader.Commands.transferFunds(newOwner = newOwner.singleKey
        //,paper = paper,tx = tx), keys = requiredKeys)
        //can add required signatures to make contract bilateral
        return tx
    }

    interface Clauses
    {
        //class Group : GroupClauseVerifier<State, Commands, >
    }


    interface Commands : CommandData
    {
        data class Move(override val contractHash: SecureHash? = null)
            : FungibleAsset.Commands.Move, Commands

        data class transferFunds(val tx: TransactionBuilder,val paper: StateAndRef<btcFundTrader.State>,
                                 val newOwner: PublicKey)
            :FungibleAsset.Commands, Commands

        class issueFunds : TypeOnlyCommandData(), Commands
    }
}





