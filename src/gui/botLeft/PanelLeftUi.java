/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package gui.botLeft;

import gui.SentinelMainUi;
import gui.botLeft.AttackSelection.AttackSelectionUi;
import gui.mainBot.PanelBotUi;
import gui.networking.AttackWorkEntry;
import gui.networking.Networker;
import gui.viewMessage.ExternalUpdater;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import javax.swing.JComboBox;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import model.SentinelHttpParam;
import util.BurpCallbacks;
import util.SettingsManager;


/**
 * UI Element of panel left
 * 
 * @author unreal
 */
public class PanelLeftUi extends javax.swing.JPanel implements ExternalUpdater {
    private PanelBotUi panelParent;
    private SentinelHttpMessageOrig origHttpMessage;
    private int selectedRow = -1;
    
    private final PanelLeftTableModel tableModel;
    private final PanelLeftComboBoxModel sessionComboBoxModel;
    private final JComboBox comboBoxSession;
    private final PanelLeftPopup paramPopup;
    private final PanelLeftOptions optionsPopup;
    private final PopupTableHeaderLeft popupTableHeaderLeft;
    private final AttackSelectionUi attackSelectionUi;

    
    /**
     * Creates new form RequestConfigForm
     */
    public PanelLeftUi() {
        attackSelectionUi = new AttackSelectionUi();
        tableModel = new PanelLeftTableModel( attackSelectionUi.getTableModel() );
        sessionComboBoxModel = new PanelLeftComboBoxModel();
        comboBoxSession = new JComboBox();
        comboBoxSession.setModel(sessionComboBoxModel);

        initComponents();
        buttonSend.setVisible(false);
        panelViewMessage.setTheme("left");

        tableMessages.getColumnModel().getColumn(0).setMaxWidth(64);
        tableMessages.getColumnModel().getColumn(0).setMinWidth(64);

        tableMessages.getColumnModel().getColumn(3).setMaxWidth(64);
        tableMessages.getColumnModel().getColumn(3).setMinWidth(64);

        tableMessages.setAutoCreateRowSorter(true);
        SettingsManager.restoreSplitLocation(jSplitPane1, this);
        SettingsManager.restoreTableDimensions(tableMessages, this);

        // column 2
        TableColumn column2 = tableMessages.getColumnModel().getColumn(2);
        TableColumn column1 = tableMessages.getColumnModel().getColumn(1);
        PanelLeftTableCellRenderer renderer = new PanelLeftTableCellRenderer(comboBoxSession);
        column2.setCellRenderer(renderer);
        column2.setCellEditor(new PanelLeftTableCellEditor(comboBoxSession));
        column1.setCellRenderer(renderer);

        // Param Popup
        paramPopup = new PanelLeftPopup(this);
        tableMessages.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (paramPopup.getPopup().isPopupTrigger(e)) {
                    JTable source = (JTable) e.getSource();
                    int row = source.rowAtPoint(e.getPoint());
                    selectedRow = row;
                    int column = source.columnAtPoint(e.getPoint());

                    if (!source.isRowSelected(row)) {
                        source.changeSelection(row, column, false, false);
                    }

                    paramPopup.refreshAttackListIndex();
                    paramPopup.getPopup().show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        tableMessages.setTableHeader(new TableHeaderTooltip(tableMessages.getColumnModel()));
        
        // Options Popup
        optionsPopup = new PanelLeftOptions();

        popupTableHeaderLeft = new PopupTableHeaderLeft(tableMessages, tableModel);
        tableMessages.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }

            private void showPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    //popupTableHeaderLeft.show(e.getComponent(), e.getX(), e.getY());
                    popupTableHeaderLeft.show(e.getComponent(), e);
                }
            }
        });
    }

    
    SentinelHttpParam getSelectedHttpParam() {
        return tableModel.getHttpParamAt(selectedRow);
    }

    
    private TableModel getTableModel() {
        return tableModel;
    }
    

    public void setMessage(SentinelHttpMessageOrig message) {
        this.origHttpMessage = message;
        tableModel.setMessage(origHttpMessage);
        panelViewMessage.setHttpMessage(origHttpMessage);
        
        if (message.getResponse() == null) {
            buttonAttack.setEnabled(false);
            buttonSend.setVisible(true);
        } else {
            buttonAttack.setEnabled(true);
            buttonSend.setVisible(false);
        }
    }

    
    /*
     * Add Attack Message
     * 
     * An attack thread did generate (and send/receive) a new message.
     * Add to right panel (call our parent, botpanelui, to do this)
     */
    public void addAttackMessage(SentinelHttpMessageAtk attackMessage) {
        panelParent.addAttackMessage(attackMessage);
    }

    
    /* 
     * Attack attackParam
     * 
     * Only we, panelLeftUi, have all the necessary information to attack.
     *
     * Called by:
     *   this.attackRessource()
     *   PanelLeftPopup.attack*()
     */
    void attackSelectedParam(UiAttackParam attackParam) {
        AttackWorkEntry attackEntry = new AttackWorkEntry(
                attackParam.param,
                attackParam.attackType,
                attackParam.attackData,
                origHttpMessage,
                this,
                optionsPopup.getOptionRedirect(),
                optionsPopup.getOptionInsertPosition(),
                (String) SentinelMainUi.getMainUi().getPanelTop().getOptionsPopup().getOptionsOrig().getSelectedSession());
                // Holy shit, a pretty long line for something which is not functional...

        Networker.getInstance().attackThis(attackEntry);
    }
    

    /* 
     * Click on "Go"
     * Attacks current httpmessage with all selected attacks
     */
    private void attackRessource() {
        // Set session options
        if (comboBoxSession.getSelectedIndex() > 0) {
            tableModel.setSessionAttackMessage(true, (String) comboBoxSession.getSelectedItem());
        }

        // Transfer UI attack ticks to HttpMessage attacks
        // The function will call attackSelectedParam() appropriatly - we are finished here.
        List<UiAttackParam> attackParamList = tableModel.getChangedParams();
        for(UiAttackParam attackParam: attackParamList) {
            attackSelectedParam(attackParam);
        }

        // reset UI attack ticks
        tableModel.resetAttackSelection();
        comboBoxSession.setSelectedIndex(0);
    }

    
    /*
     * If we add a virtual parameter (decoded version of existing one), we need
     * to update table model and redraw table.
     */
    void updateModel() {
        tableModel.reinit();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel2 = new javax.swing.JPanel();
        jSplitPane1 = new javax.swing.JSplitPane();
        panelTop = new javax.swing.JPanel();
        panelTopHeader = new javax.swing.JPanel();
        buttonAttack = new javax.swing.JButton();
        buttonOptions = new javax.swing.JButton();
        buttonPayloadSelection = new javax.swing.JButton();
        buttonSend = new javax.swing.JButton();
        panelTopBody = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        tableMessages = new javax.swing.JTable();
        panelBottom = new javax.swing.JPanel();
        panelViewMessage = new gui.viewMessage.PanelViewMessageUi();

        setLayout(new java.awt.BorderLayout());

        jPanel2.setLayout(new java.awt.BorderLayout());

        jSplitPane1.setDividerLocation(300);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        buttonAttack.setBackground(new java.awt.Color(229, 137, 0));
        buttonAttack.setText("Go");
        buttonAttack.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonAttackActionPerformed(evt);
            }
        });

        buttonOptions.setText("Options");
        buttonOptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonOptionsActionPerformed(evt);
            }
        });

        buttonPayloadSelection.setText("Attack Selection");
        buttonPayloadSelection.setToolTipText("Select the attack payloads you want to use.");
        buttonPayloadSelection.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonPayloadSelectionActionPerformed(evt);
            }
        });

        buttonSend.setBackground(new java.awt.Color(229, 137, 0));
        buttonSend.setText("Send");
        buttonSend.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonSendActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelTopHeaderLayout = new javax.swing.GroupLayout(panelTopHeader);
        panelTopHeader.setLayout(panelTopHeaderLayout);
        panelTopHeaderLayout.setHorizontalGroup(
            panelTopHeaderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelTopHeaderLayout.createSequentialGroup()
                .addComponent(buttonOptions)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(buttonPayloadSelection)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(buttonSend)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(buttonAttack, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        panelTopHeaderLayout.setVerticalGroup(
            panelTopHeaderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelTopHeaderLayout.createSequentialGroup()
                .addGroup(panelTopHeaderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(buttonAttack)
                    .addComponent(buttonOptions)
                    .addComponent(buttonPayloadSelection)
                    .addComponent(buttonSend))
                .addGap(0, 0, Short.MAX_VALUE))
        );

        tableMessages.setModel(getTableModel());
        tableMessages.setToolTipText("");
        tableMessages.setRowHeight(20);
        tableMessages.setSelectionBackground(new java.awt.Color(255, 205, 129));
        tableMessages.setSelectionForeground(new java.awt.Color(0, 0, 0));
        jScrollPane1.setViewportView(tableMessages);

        javax.swing.GroupLayout panelTopBodyLayout = new javax.swing.GroupLayout(panelTopBody);
        panelTopBody.setLayout(panelTopBodyLayout);
        panelTopBodyLayout.setHorizontalGroup(
            panelTopBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 630, Short.MAX_VALUE)
        );
        panelTopBodyLayout.setVerticalGroup(
            panelTopBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 272, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout panelTopLayout = new javax.swing.GroupLayout(panelTop);
        panelTop.setLayout(panelTopLayout);
        panelTopLayout.setHorizontalGroup(
            panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(panelTopHeader, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(panelTopBody, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        panelTopLayout.setVerticalGroup(
            panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelTopLayout.createSequentialGroup()
                .addComponent(panelTopHeader, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(2, 2, 2)
                .addComponent(panelTopBody, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jSplitPane1.setTopComponent(panelTop);

        javax.swing.GroupLayout panelBottomLayout = new javax.swing.GroupLayout(panelBottom);
        panelBottom.setLayout(panelBottomLayout);
        panelBottomLayout.setHorizontalGroup(
            panelBottomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 630, Short.MAX_VALUE)
            .addGroup(panelBottomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(panelViewMessage, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 630, Short.MAX_VALUE))
        );
        panelBottomLayout.setVerticalGroup(
            panelBottomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 147, Short.MAX_VALUE)
            .addGroup(panelBottomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(panelViewMessage, javax.swing.GroupLayout.DEFAULT_SIZE, 147, Short.MAX_VALUE))
        );

        jSplitPane1.setBottomComponent(panelBottom);

        jPanel2.add(jSplitPane1, java.awt.BorderLayout.CENTER);

        add(jPanel2, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    private void buttonAttackActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonAttackActionPerformed
        attackRessource();
    }//GEN-LAST:event_buttonAttackActionPerformed

    private void buttonOptionsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonOptionsActionPerformed
        JPopupMenu menu = optionsPopup.getPopupMenu();
        menu.show(buttonOptions, buttonOptions.getBounds().width, 0);
    }//GEN-LAST:event_buttonOptionsActionPerformed

    private void buttonPayloadSelectionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonPayloadSelectionActionPerformed
        if (attackSelectionUi.isVisible()) {
            attackSelectionUi.setVisible(false);
        } else {
            attackSelectionUi.setLocationRelativeTo(this.panelParent);
            attackSelectionUi.setVisible(true);
        }
    }//GEN-LAST:event_buttonPayloadSelectionActionPerformed

    // Send request again
    // The sender will call this.externalUpdate() upon success
    private void buttonSendActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonSendActionPerformed
        BurpCallbacks.getInstance().sendResource(origHttpMessage, true, this);
    }//GEN-LAST:event_buttonSendActionPerformed

    // Burp successfully sent the request again
    // Re-Initialize everything so we see the response
    @Override
    public void externalUpdate() {
        setMessage(origHttpMessage);
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonAttack;
    private javax.swing.JButton buttonOptions;
    private javax.swing.JButton buttonPayloadSelection;
    private javax.swing.JButton buttonSend;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JPanel panelBottom;
    private javax.swing.JPanel panelTop;
    private javax.swing.JPanel panelTopBody;
    private javax.swing.JPanel panelTopHeader;
    private gui.viewMessage.PanelViewMessageUi panelViewMessage;
    private javax.swing.JTable tableMessages;
    // End of variables declaration//GEN-END:variables

    
    public void setPanelParent(PanelBotUi aThis) {
        this.panelParent = aThis;
        panelViewMessage.setLinkManager(panelParent.getLinkManager());
    }

    
    public void storeUiPrefs() {
        SettingsManager.storeSplitLocation(jSplitPane1, this);
        SettingsManager.storeTableDimensions(tableMessages, this);

        optionsPopup.storeUiPrefs();
    }

    
    public SentinelHttpMessage getOrigHttpMessage() {
        return origHttpMessage;
    }

}
