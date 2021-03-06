package sample;

import com.sun.xml.internal.bind.v2.runtime.reflect.Lister;
import service.PacketInfo;
import javafx.application.Platform;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableBooleanValue;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.util.Callback;
import javafx.util.StringConverter;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import service.NetCard;
import service.PacketCapture;
import service.PacketFactory;

import java.net.URL;
import java.util.Map;
import java.util.ResourceBundle;

public class Controller implements Initializable {

    private Packet packet;

    private PacketCapture capture;

    private SimpleBooleanProperty scanning = new SimpleBooleanProperty(false);

    private Thread scaningThread = null;


    @FXML
    private StackPane container;
    @FXML
    private ComboBox<NetworkInterface> selectNetworkCard = new ComboBox<>();
    @FXML
    private Button start_stop;
    @FXML
    private ComboBox<String> selectProtocol = new ComboBox<>();
    @FXML
    private TextField filterMask;
    @FXML
    private Button filterAction;
    @FXML
    private TableView<PacketInfo> packetTable = new TableView<>();
    @FXML
    private TableColumn<PacketInfo,Integer> No_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> time_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> source_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> target_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> protocol_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,Integer> length_col = new TableColumn<>();
    @FXML
    private TableColumn<PacketInfo,String> info_col = new TableColumn<>();

    @FXML
    private VBox box;

    @FXML
    private TextArea detail_text;

    @FXML
    private TextArea trace_route;


    public static ObservableList<PacketInfo> packets = FXCollections.observableArrayList();


    private final ObservableList<String> protocols = FXCollections.observableArrayList(
            "",
            "IP4",
            "IP6",
            "ARP",
            "ICMP",
            "TCP",
            "UDP",
            "HTTP",
            "TLS"
    );

    private ObservableList<NetworkInterface> networkCards = FXCollections.observableArrayList();


    public void initPacketTable(){
        packetTable.prefWidthProperty().bind(container.widthProperty());
        packetTable.prefHeightProperty().bind(container.widthProperty().divide(4.0));
        No_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        time_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        source_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        target_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        protocol_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        length_col.prefWidthProperty().bind(packetTable.widthProperty().divide(9.0));
        info_col.prefWidthProperty().bind(packetTable.widthProperty().divide(3.0));

        No_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,Integer>("no"));
        time_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("time"));
        source_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("sourceIp"));
        target_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("targetIp"));
        protocol_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("protocol"));
        length_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,Integer>("length"));
        info_col.setCellValueFactory(new PropertyValueFactory<PacketInfo,String>("info"));

        packetTable.setItems(packets);


        packetTable.setRowFactory(new Callback<TableView<PacketInfo>, TableRow<PacketInfo>>() {
            @Override
            public TableRow<PacketInfo> call(TableView<PacketInfo> param) {
                return new TableRowControl();
            }
        });


    }

    class TableRowControl extends TableRow<PacketInfo>{
        public TableRowControl(){
            super();
            this.setOnMouseClicked(new EventHandler<MouseEvent>() {
                @Override
                public void handle(MouseEvent event) {
                    if (event.getButton().equals(MouseButton.PRIMARY)
                            && event.getClickCount() == 1
                            && TableRowControl.this.getIndex() < packetTable.getItems().size()) {

                        int index = TableRowControl.this.getIndex();
                        PacketInfo info = packetTable.getItems().get(index);
                        Packet p = info.getPacket();

                        Map<String,Object> m =  PacketFactory.getPacketDetail(info,p);
                        for(String key : m.keySet()){
                            System.out.println(m.get(key));
                        }

                        TreeItem<String> rootnode = new TreeItem<>();

                        box.getChildren().clear();
                        TreeItem<String> frameRoot = new TreeItem<>("frame "+(index+1)+" : "+p.header.length +" bytes on wire");
                        TreeItem<String> interfaceName = new TreeItem<>("Interface Name :"+info.getInterfaceName());
                        frameRoot.getChildren().add(interfaceName);
                        rootnode.getChildren().add(frameRoot);

                        for (String key : m.keySet()){
                            TreeItem<String> croot = null;
                            Object value = m.get(key);
                            if (value instanceof Map){
                                croot = new TreeItem<>(key);
                                Map<String,String> m1 = (Map<String,String>) value;
                                for (String key1 : m1.keySet()){
                                    TreeItem<String> treeItem = new TreeItem<>(key1+": "+m1.get(key1));
                                    croot.getChildren().add(treeItem);
                                }
                            }else if (value.getClass().equals(String.class)){
                                croot = new TreeItem<>(key+": "+value);
                            }
                            if (croot!=null){
                                rootnode.getChildren().add(croot);
                            }

                        }
                        rootnode.setExpanded(true);
                        box.getChildren().add(new TreeView<String>(rootnode));
                        detail_text.setVisible(true);
                        detail_text.setText(PacketFactory.getDetail(p));
                        trace_route.setVisible(true);
                        trace_route.setText(PacketCapture.traceRoute(info));



                    }
                }
            });
        }
    }

    public void filldata(){

        networkCards.clear();
        NetworkInterface[] networkInterfaces = NetCard.getDevices();
        for (NetworkInterface networkInterface:
                networkInterfaces) {
            networkCards.add(networkInterface);
        }
    }

    public void initCapture(){
        capture = PacketCapture.getInstance();
        bindData2Capture();


    }

    public void initConfigure(){
        //???????????????????????????
        selectProtocol.setItems(protocols);

        selectNetworkCard.setItems(networkCards);

        selectNetworkCard.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<NetworkInterface>() {
            @Override
            public void changed(ObservableValue<? extends NetworkInterface> observable, NetworkInterface oldValue, NetworkInterface newValue) {
                scanning.set(false);
                //?????????????????????
                capture.setDevice(newValue);
            }
        });

        selectNetworkCard.setConverter(new StringConverter<NetworkInterface>() {
            @Override
            public String toString(NetworkInterface object) {
                return object.name;
            }

            @Override
            public NetworkInterface fromString(String string) {
                int i = 0;
                for (;i<networkCards.size();i++){
                    if (networkCards.get(i).name.equals(string)){
                        return networkCards.get(i);
                    }
                }
                return null;
            }
        });

        selectProtocol.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                capture.setProtocolType(newValue);
            }
        });
        filterAction.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                //??????
                String filterStr = filterMask.getText();
                capture.setFilter(filterStr);
            }
        });

        start_stop.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                //???????????????????????????????????????
                if (!scanning.get()&&selectNetworkCard.getSelectionModel().getSelectedItem()==null){
                    return;
                }
                scanning.set(!scanning.get());
            }
        });

        scanning.addListener(new ChangeListener<Boolean>() {
            @Override
            public void changed(ObservableValue<? extends Boolean> observable, Boolean oldValue, Boolean newValue) {

                if (newValue){
                    start_stop.setText("??????");
                    if (scaningThread==null||!scaningThread.isAlive()){
                        capture.setRun(true);
                        scaningThread = new Thread(capture);
                    }
                    scaningThread.start();
                    System.out.println("??????????????????");
                }else {
                    start_stop.setText("??????");
                    capture.setRun(false);
                }
            }
        });
    }

    public void bindData2Capture(){
        if (capture!=null){
            capture.bindTable(packets);
        }
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        initPacketTable();
        filldata();
        initConfigure();
        initCapture();


    }



}

