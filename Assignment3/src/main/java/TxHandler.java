import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TxHandler {

    public UTXOPool currentUTXOPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        currentUTXOPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        Set<UTXO> utxos = new HashSet<UTXO>();
        double inputSum = 0.0;
        double outputSum = 0.0;

        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output prevOutput = currentUTXOPool.getTxOutput(utxo);

            // (1) all outputs claimed by {@code tx} are in the current UTXO pool,
            if (!currentUTXOPool.contains(utxo)) {
                return false;
            }

            // (2) the signatures on each input of {@code tx} are valid,
            if (!Crypto.verifySignature(prevOutput.address, tx.getRawDataToSign(i), input.signature)) {
                return false; // TODO
            }

            // (3) no UTXO is claimed multiple times by {@code tx},
            if (utxos.contains(utxo)) {
                return false;
            } else {
                utxos.add(utxo);
            }

            inputSum += prevOutput.value;
        }

        for (int i = 0; i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);

            // (4) all of {@code tx}s output values are non-negative, and
            if (output.value < 0) {
                return false;
            }
            outputSum += output.value;
        }

        // (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output values
        return outputSum <= inputSum;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> transactions = new ArrayList<Transaction>();

        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                handleTx(tx);
                transactions.add(tx);
            }
        }

        return transactions.toArray(new Transaction[0]);
    }

    private void handleTx(Transaction tx) {
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            currentUTXOPool.removeUTXO(utxo);
        }
        for (int i = 0; i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);
            currentUTXOPool.addUTXO(new UTXO(tx.getHash(), i), output);
        }
    }

}
