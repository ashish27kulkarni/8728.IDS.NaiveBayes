/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package algoPack;

/**
 *
 * @author Administrator
 */
public class NaiveBayes {
    
    public DataSet ds;
    
    int outputFrequencyCount[];
    double initialprobabilities[];
    double individualProbabilities[][];
    double finalProbabilities[];

    public NaiveBayes(DataSet ds) {
        this.ds = ds;
        
        initialprobabilities = new double[ds.outputDataLength];
        calculateInitialProbabilities();
    }
    
    void calculateInitialProbabilities() {
        outputFrequencyCount = new int[ds.outputDataLength];
        for(int i=0;i<ds.outputDataLength;i++) {
            outputFrequencyCount[i] = 0;
        }
        for(DataItem di: ds.list) {
            outputFrequencyCount[di.output]++;
        }
        for(int i=0;i<ds.outputDataLength;i++) {
            initialprobabilities[i] = outputFrequencyCount[i] * 1. / ds.list.size();
            System.out.println("INITIAL PROB FOR [" + (i) + "]: " + initialprobabilities[i]);
        }
        
    }
    
    public int classify(DataItem diTest) {
        int individualFC[][] = new int[ds.inputTotal][ds.outputDataLength];
        
        // only initialization...
        for(int inputIndex=0;inputIndex<ds.inputTotal;inputIndex++) {
            for(int outputValueIndex=0;outputValueIndex<ds.outputDataLength;outputValueIndex++) {
                individualFC[inputIndex][outputValueIndex] = 0;
            }
        }
        
        // calculating individual frequency counts...
        for(DataItem di: ds.list) {
            for(int inputIndex=0;inputIndex<ds.inputTotal;inputIndex++) {
                if(di.input[inputIndex] == diTest.input[inputIndex]) {
                    individualFC[inputIndex][di.output] ++;
                }
            }
        }
        
        // calculating individual probabilities...
        individualProbabilities = new double[ds.inputTotal][ds.outputDataLength];
        System.out.println("PROBABILITIES");
        for(int outputValueIndex=0;outputValueIndex<ds.outputDataLength;outputValueIndex++) {
            System.out.println("FOR OUTPUT: (" + outputValueIndex + ")");
            for(int inputIndex=0;inputIndex<ds.inputTotal;inputIndex++) {
                
                if(outputFrequencyCount[outputValueIndex]!=0) {
                    individualProbabilities[inputIndex][outputValueIndex] = (individualFC[inputIndex][outputValueIndex] * 1.0)/outputFrequencyCount[outputValueIndex];
                }else {
                    individualProbabilities[inputIndex][outputValueIndex] = 0;
                }
                
                System.out.println("INPUT INDEX " + inputIndex + ": " + individualProbabilities[inputIndex][outputValueIndex]);
                
            }
            System.out.println();
        }
        
        double maxProbability = 0;
        int maxProbabilityOutputValueIndex = -1;
        
        // final probabilities
        finalProbabilities = new double[ds.outputDataLength];
        for(int outputValueIndex=0;outputValueIndex<ds.outputDataLength;outputValueIndex++) {
            
            finalProbabilities[outputValueIndex] = initialprobabilities[outputValueIndex];
            
            // multiply by rest
            for(int inputIndex=0;inputIndex<ds.inputTotal;inputIndex++) {
                finalProbabilities[outputValueIndex] *= individualProbabilities[inputIndex][outputValueIndex];
            }
            System.out.println("Final Probability For Output Value " + outputValueIndex + ": " + finalProbabilities[outputValueIndex]);
            
            // initialization for first index
            if(maxProbabilityOutputValueIndex==-1) {
                maxProbabilityOutputValueIndex = 0;
                maxProbability = finalProbabilities[outputValueIndex];
            }
            
            // compare and update best probability there after...
            if(maxProbability < finalProbabilities[outputValueIndex]) {
                maxProbabilityOutputValueIndex = outputValueIndex;
                maxProbability = finalProbabilities[outputValueIndex];
            }
        }
        
        return maxProbabilityOutputValueIndex;
    }
    
    
//    
//    public void classify(DataSet ds) {
//        
//        int totalItemsLeftToConsider = 0;
//        for(int inputIndex=0;inputIndex<ds.inputTotal;inputIndex++) {
//            if(ds.inputDataConsider[inputIndex] == 1) {
//                totalItemsLeftToConsider++;
//            }
//        }
//        if(totalItemsLeftToConsider < 2) {
//            System.out.println("Not Enough Items Left To Create A SubTree!");
//            return;
//        }
//        
//        // calculating probability
//        int freqOp[] = new int[ds.outputDataLength];
//        double probOp[] = new double[ds.outputDataLength];
//        double entropy = 0;
//        
//        for(int i=0;i<ds.outputDataLength;i++) {
//            freqOp[i] = 0;
//        }
//        int totalRecords = 0;
//        for(DataItem di : ds.list) {
//            freqOp[di.output]++;
//            totalRecords++;
//        }
//        for(int i=0;i<ds.outputDataLength;i++) {
//            probOp[i] = freqOp[i] * 1. / totalRecords;
//        }
//        
//        entropy = 0;
//        for(int i=0;i<ds.outputDataLength;i++) {
//            entropy += probOp[i] * myLog(probOp[i]);
//        }
//        entropy *= -1;
//        System.out.println("ENTROPY: " + entropy);
//        
//        double individualEntropy[] = new double[ds.inputTotal];
//        double gain[] = new double[ds.inputTotal];
//        totalRecords = ds.list.size();
//        int maxIndex = -1;
//        double maxGain = 0;
//        
//        for(int inputIndex=0;inputIndex<ds.inputTotal;inputIndex++) {
//            
//            // proceed only if consider = true
//            if(ds.inputDataConsider[inputIndex] != 1) {
//                continue;
//            }
//            
//            individualEntropy[inputIndex] = 0;
//            gain[inputIndex] = 0;
//            for(int inputValue=0;inputValue<ds.inputDataLength[inputIndex];inputValue++) {
//                int totalRecordsMatchingInput = getTotalRecordsMatchingInput(ds, inputIndex, inputValue);
//                if(totalRecordsMatchingInput!=0) {
//                    individualEntropy[inputIndex] += (totalRecordsMatchingInput * 1. / totalRecords) * getEntropyForInput(ds, inputIndex, inputValue);
//                }
//            }
//            
//            if(Double.isNaN(individualEntropy[inputIndex])) {
//                System.out.println("FOR INPUT " + (inputIndex+1) + ": NaN : " + gain[inputIndex]);
//                continue;
//            }
//            gain[inputIndex] = entropy - individualEntropy[inputIndex];
//            
//            if(maxIndex==-1) {
//                maxIndex = inputIndex;
//                maxGain = gain[inputIndex];
//            }else {
//                if(maxGain < gain[inputIndex]) {
//                    maxGain = gain[inputIndex];
//                    maxIndex = inputIndex;
//                }
//            }
//            System.out.println("FOR INPUT " + (inputIndex+1) + ": " + gain[inputIndex]);
//        }
//        System.out.println("MAX INDEX: " + maxIndex);
//        
//        if(maxIndex==-1) {
//            return;
//        }
//        ds.generateNewDataSets(maxIndex);
//        
//        for(DataSet dsChild: ds.leaf) {
//            applyAlgo(dsChild);
//            dsChild.printShortDetails();
//        }
//    }
//    
//    int getTotalRecordsMatchingInput(DataSet ds, int inputIndex, int inputValue) {
//        int totalRecords = 0;
//        for(DataItem di: ds.list) {
//            if(di.input[inputIndex] == inputValue) {
//                totalRecords++;
//            }
//        }
//        return totalRecords;
//    }
//    
//    double getEntropyForInput(DataSet ds, int inputIndex, int inputValue) {
//        // calculating probability
//        int freqOp[] = new int[ds.outputDataLength];
//        double probOp[] = new double[ds.outputDataLength];
//        double entropy = 0;
//        
//        for(int i=0;i<ds.outputDataLength;i++) {
//            freqOp[i] = 0;
//        }
//        int totalRecords = 0;
//        for(DataItem di : ds.list) {
//            if(di.input[inputIndex]==inputValue) {
//                freqOp[di.output]++;
//                totalRecords++;
//            }
//        }
//        for(int i=0;i<ds.outputDataLength;i++) {
//            if(totalRecords!=0) {
//                probOp[i] = freqOp[i] * 1. / totalRecords;
//            }else {
//                probOp[i] = 0;
//            }
//        }
//        entropy = 0;
//        System.out.print("Entropy For Input Index: " + inputIndex + " For Value : " + inputValue);
//        for(int i=0;i<ds.outputDataLength;i++) {
//            System.out.print(" PROB: " + probOp[i] + " ");
//            if(probOp[i]!=0) {
//                entropy += probOp[i] * myLog(probOp[i]);
//            }
//        }
//        System.out.println(" : " + entropy);
//        
//        entropy *= -1;
//        return entropy;
//    }

    
}
