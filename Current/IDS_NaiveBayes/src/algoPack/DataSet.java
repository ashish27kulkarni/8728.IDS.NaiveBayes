/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package algoPack;

import java.util.Vector;


public class DataSet {
    public Vector <DataItem> list;
    public int inputTotal;
    
    public int inputDataLength[];
    public int outputDataLength;
    
    
    public DataSet() {
        list = new Vector<DataItem>();
        inputTotal = 0;
        inputDataLength = null;
        outputDataLength = 0;
    }
    
    public DataSet(int inputTotal, int inputDataLength[], int outputDataLength) {
        this.inputTotal = inputTotal;
        this.inputDataLength = inputDataLength.clone();
        this.outputDataLength = outputDataLength;
        
        list = new Vector<DataItem>();
    }
    
}

