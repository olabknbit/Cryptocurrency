import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/* CompliantNode refers to a node that follows the rules (not malicious)*/
public class CompliantNode implements Node {

    class MyCandidate extends Candidate {

        public MyCandidate(Transaction tx, int sender) {
            super(tx, sender);
        }

        public MyCandidate(Candidate candidate) {
            this(candidate.tx, candidate.sender);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final MyCandidate other = (MyCandidate) obj;
            if (this.tx.id != other.tx.id || this.sender != other.sender) {
                return false;
            }
            return true;
        }

        @Override
        public int hashCode() {
            return tx.id * 13 + sender;
        }
    }

    private final double p_graph;
    private final double p_malicious;
    private final double p_txDistribution;
    private final int numRounds;
    private int currentRound;
    private boolean[] followees;

    private Set<Transaction> allTransactions;
    private Set<Transaction> newTransactions;
    private Set<MyCandidate> prevCandidates;
    private Map<MyCandidate, Integer> map;

    private boolean[] malicious;

    public CompliantNode(double p_graph, double p_malicious, double p_txDistribution, int numRounds) {
        this.p_graph = p_graph;
        this.p_malicious = p_malicious;
        this.p_txDistribution = p_txDistribution;
        this.numRounds = numRounds;
        this.currentRound = 0;
        this.followees = null;
        this.prevCandidates = new HashSet<>();
    }

    public void setFollowees(boolean[] followees) {
        this.followees = followees;
        this.malicious = new boolean[followees.length];
    }

    public void setPendingTransaction(Set<Transaction> pendingTransactions) {
        this.allTransactions = pendingTransactions;
        this.newTransactions = pendingTransactions;
    }

    public Set<Transaction> sendToFollowers() {
        Set<Transaction> toBeSent;
        if (currentRound < numRounds) {
            toBeSent = newTransactions;
        } else {

            toBeSent = allTransactions;
        }
        allTransactions.addAll(newTransactions);
        newTransactions = new HashSet<>();
        currentRound++;
        return toBeSent;
    }

    public void receiveFromFollowees(Set<Candidate> candidates) {
        for (Candidate candidate : candidates) {
            if (prevCandidates.contains(new MyCandidate(candidate))) {
                // Node should not sent the same candidate again, if it did => that sender is a malicious node.
                malicious[candidate.sender] = true;
            } else {
                // Otherwise add that candidate to previously sent candidates.
                prevCandidates.add(new MyCandidate(candidate));
                if (!allTransactions.contains(candidate.tx)) {
                    newTransactions.add(candidate.tx);
                }
            }
        }
    }
}
