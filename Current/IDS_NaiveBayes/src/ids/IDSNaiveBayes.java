package ids;

import idsDataLib.SinglePacket;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.sql.SQLException;
import JavaLib.*;
import algoPack.DataItem;
import java.io.PrintStream;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import jpcap.JpcapCaptor;
import jpcap.packet.*;
import sun.net.smtp.SmtpClient;

public class IDSNaiveBayes extends javax.swing.JFrame {

    MainForm parent;
    
    public boolean threadRunning;
    
    Object[] colHeaderIncoming = new Object[] {"INCOMING PACKET DETAILS"};
    Object[] colHeaderIDS = new Object[] {"DATE-TIME", "IDS DETAILS"};
    DefaultTableModel tmIncoming;
    DefaultTableModel tmIDS;

    int deviceIndex;
    
    public IDSNaiveBayes(MainForm parent, int deviceIndex) {
        this.parent = parent;
        this.deviceIndex = deviceIndex;
        
        
        initComponents();
        
        Dimension sd = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation(sd.width / 2 - this.getWidth() / 2, sd.height / 2 - this.getHeight() / 2);
        
        threadRunning = false;

        tmIncoming = new DefaultTableModel(colHeaderIncoming, 0);
        jTableIncoming.setModel(tmIncoming);
        
        tmIDS = new DefaultTableModel(colHeaderIDS, 0);
        jTableIDS.setModel(tmIDS);
        clearTableIDS();
    }
    
    public void clearTableIDS() {
        tmIDS = new DefaultTableModel(colHeaderIDS, 0);
        jTableIDS.setModel(tmIDS);
    }
    
    public void addToTableIncoming(String str) {
        Object colData[] = new Object[]{str};
        tmIncoming.insertRow(0, colData);
        if(tmIncoming.getRowCount() > 50) {
            tmIncoming.removeRow(50);
        }
        jTableIncoming.setModel(tmIncoming);
    }
    
    public void addToTableIDS(Object colData[]) {
        tmIDS.insertRow(0, colData);
        jTableIDS.setModel(tmIDS);
    }    
    
    class CaptureTimerTask extends TimerTask {
        IDSNaiveBayes parent;
        int img;
        
        CaptureTimerTask(IDSNaiveBayes parent) {
            this.parent = parent;
            img = 0;
            
        }
        
        public void run() {
            try {
                JpcapCaptor jpcap = JpcapCaptor.openDevice(parent.parent.devices[deviceIndex], 65535, true, 20);
                
                while (parent.threadRunning) {
                    
                    img++;
                    if(img==6) {
                        img = 0;
                    }
                    parent.jLabelStatus.setIcon(new ImageIcon(System.getProperty("user.dir") + "\\src\\zImgPack\\" + img + ".png"));
                    
                    Packet packet = jpcap.getPacket();
                    if (packet == null) {
                        try {
                            Thread.sleep(10);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            continue;
                        }
                    } else if (packet instanceof TCPPacket) {
                        TCPPacket tcpPacket = (TCPPacket) packet;
                        // check only for incoming packets...
                        if(tcpPacket.dst_ip.getHostAddress().contains(parent.parent.myAddress)) {
                            //System.out.println("TCP SOURCE PORT: " + tcpPacket.src_port + ", IP: " + tcpPacket.src_ip + ", DST PORT: " + tcpPacket.dst_port + ", HOP Limit: " + tcpPacket.hop_limit + ", Len: " + tcpPacket.data.length + ", SYN:" + tcpPacket.syn + ", ACK:" + tcpPacket.ack + ", RST: " + tcpPacket.rst + ", FIN: " + tcpPacket.fin);
                            SinglePacket sp = SinglePacket.createTCPPacket(tcpPacket.src_ip.toString(), tcpPacket.src_port, tcpPacket.dst_port, tcpPacket.hop_limit, tcpPacket.data.length , tcpPacket.syn, tcpPacket.ack, tcpPacket.rst, tcpPacket.fin);
                            
                            parent.addToTableIncoming(sp.toString());
                            parent.analysePacket(sp);
                        }
                    } else if (packet instanceof ICMPPacket) {
                        ICMPPacket icmpPacket = (ICMPPacket) packet;
                        // check only for incoming packets...
                        if(icmpPacket.dst_ip.getHostAddress().contains(parent.parent.myAddress)) {
                            //System.out.println("ICM TYPE: " + icmpPacket.type + " CODE: " + icmpPacket.code + ", ID: " + icmpPacket.id + ", LEN: " + icmpPacket.len + ", LENGTH:" + icmpPacket.length + ", :" + icmpPacket.src_ip);
                            SinglePacket sp = SinglePacket.createICMPPacket(icmpPacket.src_ip.toString(), icmpPacket.len, icmpPacket.type, icmpPacket.code);
                            
                            parent.addToTableIncoming(sp.toString());
                            parent.analysePacket(sp);
                        }
                    } else if (packet instanceof UDPPacket) {
                        UDPPacket udpPacket = (UDPPacket) packet;
                        // check only for incoming packets...
                        if(udpPacket.dst_ip.getHostAddress().contains(parent.parent.myAddress)) {
                            //System.out.println("UDP SOURCE PORT: " + udpPacket.src_port + ", IP: " + udpPacket.src_ip + ", DST PORT: " + udpPacket.dst_port + ", HOP Limit: " + udpPacket.hop_limit + ", Len: " + udpPacket.length);
                            SinglePacket sp = SinglePacket.createUDPPacket(udpPacket.src_ip.toString(), udpPacket.src_port, udpPacket.dst_port, udpPacket.hop_limit, udpPacket.data.length);
                            
                            parent.addToTableIncoming(sp.toString());
                            parent.analysePacket(sp);
                        }
                    }                    
                }
            }catch(Exception e) {
                System.out.println("Exception: " + e);
                e.printStackTrace();
            }
        }
    }
    
    public void analysePacket(SinglePacket sp) {
        int curr_in[] = sp.getInputFeatures();
        for(int i=0;i<curr_in.length;i++) {
            System.out.print(curr_in[i] + " ");
        }
        System.out.println(" PACKET: " + sp.toString());
        
        DataItem di = new DataItem(sp.getInputFeatures(), 0);
        int output = parent.nb.classify(di);

        if(output == 0) { // ok
            return;
        }
        
        Calendar c = Calendar.getInstance();
        String dt = c.get(c.YEAR) + "-" + (c.get(c.MONTH)+1) + "-" + c.get(c.DAY_OF_MONTH) + " " + c.get(c.HOUR_OF_DAY) + ":" + c.get(c.MINUTE) + ":" + c.get(c.SECOND);
        String result = "";

        result = "Detected Possible Attack From I/P: " + sp.sourceIP + " (" + sp.toString() + ")";
        
        if(jCheckEmailAlerts.isSelected()) {
            sendMail(parent.dbAdmin.smtpServer, parent.dbAdmin.serverEmailID, parent.dbAdmin.adminEmailID, "INTRUSION DETECTED", result);
        }
        
//        if(curr_out_I[1] == 1) { // syn flood
//            result = "Detected Possible SYN-Flood/TCP Attack From I/P: " + sp.sourceIP + " (" + sp.toString() + ")";
//        }else if(curr_out_I[2]==1) { // ping flood
//            result = "Detected Possible Ping-Flood Attack From I/P: " + sp.sourceIP + " (" + sp.toString() + ")";
//        }else if(curr_out_I[3]==1) { // udp flood
//            result = "Detected Possible UDP Flood Attack From I/P: " + sp.sourceIP + " (" + sp.toString() + ")";
//        }else {
//            System.out.println("Unrecognized Pattern : " + sp.toString());
//            return;
//        }
        
        addToTableIDS(new Object[] {dt, result});
    }
    
    public void sendMail(String smtp, String from, String to, String sub, String msg) {
        try {
            // from and to
            SmtpClient sc = new SmtpClient(smtp);
            sc.from(from);
            sc.to(to);

            PrintStream ps = sc.startMessage();

            // additional headers, subject et al.
            ps.println("From: " + from);
            ps.println("To: " + to);
            ps.println("Subject: " + sub);

            // blank line separates the headers and message
            ps.println();
            ps.println(msg);
            sc.closeServer();
            
            System.out.println("Mail Sent Successfully!");
        } catch (IOException e) {
            System.out.println("Error Sending Mail!");
            System.err.println(e);
        }
    }
    
    public int[] convertToInt(double outD[]) {
        int outI[] = new int[outD.length];
        for(int i=0;i<outD.length;i++) {
            if(outD[i] < 0.5) {
                outI[i] = 0;
            }else {
                outI[i] = 1;
            }
        }
        return outI;
    }
    
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jButton1 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jPanel2 = new javax.swing.JPanel();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTableIDS = new javax.swing.JTable();
        jPanel5 = new javax.swing.JPanel();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jLabelStatus = new javax.swing.JLabel();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTableIncoming = new javax.swing.JTable();
        jCheckEmailAlerts = new javax.swing.JCheckBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBackground(new java.awt.Color(51, 0, 51));
        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        jButton1.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jButton1.setText("B A C K");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 24)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(255, 255, 255));
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("IDS USING NAIVE BAYES");

        jPanel2.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "DETECTED PACKETS", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jTableIDS.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane2.setViewportView(jTableIDS);

        new LoadForm();

        jPanel5.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jButton2.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jButton2.setText("START");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jButton3.setText("STOP");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jButton4.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jButton4.setText("CLEAR DATA");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        jLabelStatus.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelStatus.setIcon(new javax.swing.ImageIcon(getClass().getResource("/zImgPack/0.png"))); // NOI18N
        jLabelStatus.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton4, javax.swing.GroupLayout.DEFAULT_SIZE, 118, Short.MAX_VALUE)
                    .addComponent(jLabelStatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jButton2)
                .addGap(18, 18, 18)
                .addComponent(jLabelStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 148, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(jButton3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButton4)
                .addContainerGap())
        );

        jPanel5Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton2, jButton3});

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 801, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                .addContainerGap())
        );

        jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "INCOMING PACKETS", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jTableIncoming.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(jTableIncoming);

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1)
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 192, Short.MAX_VALUE)
                .addContainerGap())
        );

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jCheckEmailAlerts.setText("Email Alerts");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jCheckEmailAlerts)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(jCheckEmailAlerts))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        threadRunning = false;
        
        setVisible(false);
        parent.setVisible(true);        
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:

        if(threadRunning) {
            new MessageBox(this, "Scanner Thread Already Running!").setVisible(true);
            return;
        }
        
        threadRunning = true;
        CaptureTimerTask ctt = new CaptureTimerTask(this);
        Timer captureTimer = new Timer();
        captureTimer.schedule(ctt, 100);
        
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        // TODO add your handling code here:
        if(!threadRunning ) {
            new MessageBox(this, "No Thread Running!").setVisible(true);
            return;
        }
        
        threadRunning = false;
        
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed
        // TODO add your handling code here:
        clearTableIDS();
        
    }//GEN-LAST:event_jButton4ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JCheckBox jCheckEmailAlerts;
    private javax.swing.JLabel jLabel1;
    public javax.swing.JLabel jLabelStatus;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTable jTableIDS;
    private javax.swing.JTable jTableIncoming;
    // End of variables declaration//GEN-END:variables
}
