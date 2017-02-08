package net.corda.core.schemas


import net.corda.core.crypto.CompositeKey
import net.corda.core.crypto.Party
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.Table

/**
 * Created by sangalli on 24/01/2017.
 */

object btcFundTraderSchemaV1

/**
 * Schema for the bitcoin fund trader contract.
 */
object btcFundTraderSchema : MappedSchema(schemaFamily = btcFundTraderSchema.javaClass, version = 1, mappedTypes = listOf(PersistentBtcFundTraderSchema::class.java)) {
    @Entity
    @Table(name = "cp_states")
    class PersistentBtcFundTraderSchema(

            @Column(name = "currencySymbol")
            val currencySymbol: String,

            @Column(name = "currentPrice")
            var currentPrice: Int,

            @Column(name = "notary")
            val notary: Party,

            @Column(name = "issuer")
            val issuer: Party,

            @Column(name = "owner")
            val owner: CompositeKey,

            @Column(name = "amount")
            val amount: Int,

            @Column(name = "ID")
            val id: String,

            @Column(name = "bitcoinAddress")
            val bitcoinAddress: String

    ) : PersistentState()
}

