//package net.corda.core.contracts
//
//import com.r3corda.contracts.asset.FungibleAsset
//import com.r3corda.contracts.asset.sumCashBy
//import com.r3corda.contracts.clause.AbstractIssue
//import com.r3corda.core.contracts.*
//import com.r3corda.core.contracts.clauses.AnyComposition
//import com.r3corda.core.contracts.clauses.Clause
//import com.r3corda.core.contracts.clauses.GroupClauseVerifier
//import com.r3corda.core.contracts.clauses.verifyClause
//import com.r3corda.core.crypto.Party
//import com.r3corda.core.crypto.SecureHash
//import com.r3corda.core.crypto.toBase58String
//import com.r3corda.core.schemas.MappedSchema
//import com.r3corda.core.schemas.PersistentState
//import com.r3corda.core.schemas.QueryableState
//import com.r3corda.core.transactions.TransactionBuilder
//import com.r3corda.schemas.DVLIdentitySchemaV1
//import com.r3corda.schemas.btcFundTraderSchema
//import net.corda.core.crypto.Party
//import net.corda.core.schemas.QueryableState
//import java.security.PublicKey
//import java.time.Instant
//import java.util.*
//
///**
// * Created by sangalli on 23/01/2017, adapted from CommercialPaper.kt.
// */
//
//class btcFundTrader : Contract
//{
//    data class State(
//            val currencySymbol: String = "BTC",
//            val currentPrice: Int,
//            val amount: Int,
//            val notary: Party,
//            val issuer: Party,
//            override val owner: PublicKey,
//            val bitcoinAddress: String,
//
//            val idImageURL: String
//    ): OwnableState, QueryableState, BitcoinOwnershipInformation {
//        override val dealerMasterKey = bitcoinAddress
//        override val identification = idImageURL
//        override val contract = CP_PROGRAM_ID
//        override val participants: List<PublicKey>
//            get() = listOf(owner)
//        override fun withNewOwner(newOwner: PublicKey) =
//                Pair(CommercialPaper.Commands.Move(), copy(owner = newOwner))
//        /** Object Relational Mapping support. */
//        override fun supportedSchemas(): Iterable<MappedSchema> = listOf(btcFundTraderSchema)
//        /** Object Relational Mapping support. */
//        override fun generateMappedObject(schema: MappedSchema): PersistentState {
//            return when (schema) {
//                is btcFundTraderSchema -> btcFundTraderSchema.PersistentBtcFundTraderSchema(
//                        currencySymbol = currencySymbol,
//                        currentPrice = 1200,
//                        issuer = issuer,
//                        notary = notary,
//                        owner = owner,
//                        amount = amount,
//                        id = idImageURL,
//                        bitcoinAddress = bitcoinAddress
//                )
//                else -> throw IllegalArgumentException("Unrecognised schema $schema")
//            }
//        }
//    }
//
//
//    override val legalContractReference: SecureHash = SecureHash.sha256("BTCFUND trade commencing on: "
//            + Instant.now())
//
//    override fun verify(transaction: TransactionForContract) {
//        verifyClause(transaction, CommercialPaper.Clauses.Group(),
//                transaction.commands.select<CommercialPaper.Commands>())
//    }
//
//    fun generateTransaction(state : State) : TransactionBuilder
//    {
//        val tx = TransactionType.General.Builder(notary = state.notary).withItems(state,
//                Command(btcFundTrader.Commands.Move(), state.issuer.owningKey))
//        return tx
//    }
//
//    /**
//     * Updates the given partial transaction with an input/output/command to reassign ownership of the paper.
//     */
//    fun transferFunds (tx: TransactionBuilder, paper: StateAndRef<btcFundTrader.State>, newOwner: PublicKey)
//            : TransactionBuilder
//    {
//        tx.addInputState(paper)
//        tx.addOutputState(TransactionState(paper.state.data.copy(owner = newOwner), paper.state.notary))
//        tx.addCommand(btcFundTrader.Commands.Move(), paper.state.data.owner)
//
//        return tx
//    }
//
////    interface Clauses {
////        class Transfer : AbstractIssue<State, Commands, Clauses>(
////
////        )
////    }
//
//
//    interface Commands : CommandData
//    {
//        data class Move(override val contractHash: SecureHash? = null)
//            : FungibleAsset.Commands.Move, Commands
//
//        data class transferFunds(val tx: TransactionBuilder,val paper: StateAndRef<btcFundTrader.State>,
//                                 val newOwner: PublicKey)
//            :FungibleAsset.Commands, Commands
//    }
//}
//
//
//
//
//
