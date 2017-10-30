package ids;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.util.Timer;
import java.util.TimerTask;
import JavaLib.*;
import idsDataLib.SinglePacket;
import javax.swing.ImageIcon;
import javax.swing.table.DefaultTableModel;
import jpcap.JpcapCaptor;
import jpcap.packet.*;

public class CapturePackets extends javax.swing.JFrame {

    MainForm parent;
    
    public boolean threadRunning;
    
    Object[] colHeader = new Object[] {"PACKET DETAILS"};
    DefaultTableModel tm;

    int deviceIndex;
    
    public CapturePackets(MainForm parent, int deviceIndex) {
        this.parent = parent;
        this.deviceIndex = deviceIndex;
        
        initComponents();
        
        Dimension sd = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation(sd.width / 2 - this.getWidth() / 2, sd.height / 2 - this.getHeight() / 2);
        
        threadRunning = false;
        clearTable();
    }
    
    public void clearTable() {
        tm = new DefaultTableModel(colHeader, 0);
        jTablePackets.setModel(tm);
    }
    
    public void addToTable(String str) {
        Object colData[] = new Object[]{str};
        tm.insertRow(0, colData);
        jTablePackets.setModel(tm);
        System.out.println("adding!");
    }
    
    class CaptureTimerTask extends TimerTask {
        CapturePackets parent;
        int img;
        
        CaptureTimerTask(CapturePackets parent) {
            this.parent = parent;
            img = 0;
        }
        
        public void run() {
            try {
                JpcapCaptor jpcap = JpcapCaptor.openDevice(parent.parent.devices[deviceIndex], 65535, true, 20);
                
                System.out.println("BEFORE!");
                
                parent.parent.currPackets.clear();
                parent.clearTable();

                while (parent.threadRunning) {
                    
                    Packet packet = jpcap.getPacket();
                    
                    if (packet == null) {
                        try {
                            Thread.sleep(1);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            continue;
                        }
                    }else {
                        System.out.println("PACKET: " + packet.toString());
                    //    addToTable(packet.toString());
                        img++;
                        if(img==6) {
                            img = 0;
                        }
                        parent.jLabelStatus.setIcon(new ImageIcon(System.getProperty("user.dir") + "\\src\\zImgPack\\" + img + ".png"));
                    }
                    
                    if(packet==null) {
                        ;
                    }else if (packet instanceof TCPPacket) {
                        
                        TCPPacket tcpPacket = (TCPPacket) packet;
                        // check only for incoming packets...
                        if(tcpPacket.dst_ip.getHostAddress().contains(parent.parent.myAddress)) {
                            System.out.println("TCP SOURCE PORT: " + tcpPacket.src_port + ", IP: " + tcpPacket.src_ip + ", DST PORT: " + tcpPacket.dst_port + ", HOP Limit: " + tcpPacket.hop_limit + ", Len: " + tcpPacket.data.length + ", SYN:" + tcpPacket.syn + ", ACK:" + tcpPacket.ack + ", RST: " + tcpPacket.rst + ", FIN: " + tcpPacket.fin);
                            
                            SinglePacket sp = SinglePacket.createTCPPacket(tcpPacket.src_ip.toString(), tcpPacket.src_port, tcpPacket.dst_port, tcpPacket.hop_limit, tcpPacket.data.length , tcpPacket.syn, tcpPacket.ack, tcpPacket.rst, tcpPacket.fin);
                            parent.parent.currPackets.add(0,sp);
                            parent.addToTable(sp.toString());
                        }else {
                            //System.out.println("FROM MY SYSTEM TCP: " + tcpPacket.src_port + ", IP: " + tcpPacket.src_ip + ", DST PORT: " + tcpPacket.dst_port + ", HOP Limit: " + tcpPacket.hop_limit + ", Len: " + tcpPacket.data.length + ", SYN:" + tcpPacket.syn + ", ACK:" + tcpPacket.ack + ", RST: " + tcpPacket.rst + ", FIN: " + tcpPacket.fin);
                        }
                    } else if (packet instanceof ICMPPacket) {
                        ICMPPacket icmpPacket = (ICMPPacket) packet;
                        // check only for incoming packets...
                        if(icmpPacket.dst_ip.getHostAddress().contains(parent.parent.myAddress)) {
                            System.out.println("ICM TYPE: " + icmpPacket.type + " CODE: " + icmpPacket.code + ", ID: " + icmpPacket.id + ", LEN: " + icmpPacket.len + ", LENGTH:" + icmpPacket.length + ", :" + icmpPacket.src_ip);
                            
                            SinglePacket sp = SinglePacket.createICMPPacket(icmpPacket.src_ip.toString(), icmpPacket.len, icmpPacket.type, icmpPacket.code);
                            parent.parent.currPackets.add(0,sp);
                            parent.addToTable(sp.toString());
                        }else {
                            //System.out.println("FROM MY SYSTEM ICMP: " + icmpPacket.type + " CODE: " + icmpPacket.code + ", ID: " + icmpPacket.id + ", LEN: " + icmpPacket.len + ", LENGTH:" + icmpPacket.length + ", :" + icmpPacket.src_ip);
                        }
                    } else if (packet instanceof UDPPacket) {
                        UDPPacket udpPacket = (UDPPacket) packet;
                        // check only for incoming packets...
                        if(udpPacket.dst_ip.getHostAddress().contains(parent.parent.myAddress)) {
                            System.out.println("UDP SOURCE PORT: " + udpPacket.src_port + ", IP: " + udpPacket.src_ip + ", DST PORT: " + udpPacket.dst_port + ", HOP Limit: " + udpPacket.hop_limit + ", Len: " + udpPacket.length);
                            
                            SinglePacket sp = SinglePacket.createUDPPacket(udpPacket.src_ip.toString(), udpPacket.src_port, udpPacket.dst_port, udpPacket.hop_limit, udpPacket.data.length);
                            parent.parent.currPackets.add(0,sp);
                            parent.addToTable(sp.toString());
                        }else {
                            //System.out.println("FROM MY SYSTEM UDP: " + udpPacket.src_port + ", IP: " + udpPacket.src_ip + ", DST PORT: " + udpPacket.dst_port + ", HOP Limit: " + udpPacket.hop_limit + ", Len: " + udpPacket.length);
                        }
                    }
                    
                    if(parent.jCheckStopAt100.isSelected() && parent.parent.currPackets.size()>=100) {
                        parent.threadRunning = false;
                    }
                    
                    // limit size to last 100 packets only...
                    if(parent.parent.currPackets.size() > 100) {
                        parent.parent.currPackets.remove(100);
                    }
                    
                }
            }catch(Exception e) {
                System.out.println("Exception: " + e);
                e.printStackTrace();
            }
        }
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
        jScrollPane1 = new javax.swing.JScrollPane();
        jTablePackets = new javax.swing.JTable();

        new LoadForm();
        jPanel3 = new javax.swing.JPanel();
        jButton2 = new javax.swing.JButton();
        jCheckStopAt100 = new javax.swing.JCheckBox();
        jButton3 = new javax.swing.JButton();
        jLabelStatus = new javax.swing.JLabel();

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
        jLabel1.setText("REAL TIME DATA CAPTURING");

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        jTablePackets.setModel(new javax.swing.table.DefaultTableModel(
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
        jScrollPane1.setViewportView(jTablePackets);

        jPanel3.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jButton2.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jButton2.setText("START");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jCheckStopAt100.setText("Stop At 100");

        jButton3.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jButton3.setText("STOP");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jLabelStatus.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelStatus.setIcon(new javax.swing.ImageIcon(getClass().getResource("/zImgPack/0.png"))); // NOI18N
        jLabelStatus.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jCheckStopAt100)
                    .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabelStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 118, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButton2)
                .addGap(18, 18, 18)
                .addComponent(jCheckStopAt100)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabelStatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(33, 33, 33)
                .addComponent(jButton3)
                .addContainerGap())
        );

        jPanel3Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton2, jButton3});

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 611, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 525, Short.MAX_VALUE)
                    .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
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
                .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(jButton1)
                .addContainerGap())
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
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
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

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JCheckBox jCheckStopAt100;
    private javax.swing.JLabel jLabel1;
    public javax.swing.JLabel jLabelStatus;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTablePackets;
    // End of variables declaration//GEN-END:variables
}
