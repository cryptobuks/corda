package net.corda.core.contracts

import net.corda.core.contracts.clauses.AnyOf
import net.corda.core.contracts.clauses.Clause
import net.corda.core.contracts.clauses.GroupClauseVerifier
import net.corda.core.contracts.clauses.verifyClause
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
 * Created by James Sangalli on 23/01/2017
 */

class btcFundTrader : Contract
{

    data class Terms(
            val id : String,
            val btcAddress : String
    )

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

    override fun verify(tx: TransactionForContract) {
        verifyClause(tx, clause = Clauses.Group(), commands = tx.commands.select<Commands>())
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
        //tx.addCommand(btcFundTrader.Commands.transferFunds(tx = tx, paper = paper, newOwner = newOwner.singleKey))
        return tx
    }

    interface Clauses {

        class Group : GroupClauseVerifier<State, Commands, Issued<Terms>>(
                AnyOf( Transfer() )) {
            override fun groupStates(tx: TransactionForContract): List<TransactionForContract.InOutGroup<State,
                    Issued<Terms>>> {
                throw UnsupportedOperationException("not implemented")
            }
        }

        class Transfer : Clause<State, Commands, Issued<Terms>>() {

            override val requiredCommands: Set<Class<out CommandData>>
                get() = setOf(Commands.Move::class.java)

            override fun verify(tx: TransactionForContract,
                                inputs: List<State>,
                                outputs: List<State>,
                                commands: List<AuthenticatedObject<Commands>>,
                                groupingKey: Issued<Terms>?): Set<Commands> {
                val command = commands.requireSingleCommand<Commands.transferFunds>()
                val input = inputs.single()
                requireThat {
                    "the transaction is signed by the owner" by (input.owner in command.signers)
                    "the state is propagated" by (outputs.size == 1)
                    "an ID is present" by (input.idImageURL != "" || input.idImageURL != null)
                    "a bitcoin address is provided" by (input.bitcoinAddress.length == 34 ||
                            input.bitcoinAddress.length == 33) //all bitcoin addresses are either 34 or 33 characters long
                }
                return setOf(command.value)
            }
        }
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
