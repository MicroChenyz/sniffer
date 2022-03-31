//package sample;
//
//import javafx.application.Application;
//import javafx.fxml.FXMLLoader;
//import javafx.scene.Parent;
//import javafx.scene.Scene;
//import javafx.stage.Stage;
//import pcap.PacketCapture;
//
//import java.util.Objects;
//
//
//public class Main extends Application {
//
//
//    @Override
//    public void start(Stage primaryStage) throws Exception{
//        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("sample.fxml")));
//        primaryStage.setTitle("网络嗅探器");
//        primaryStage.setScene(new Scene(root, 1360, 800));
//        primaryStage.show();
//    }
//
//
//    public static void main(String[] args) {
//        launch(args);
//    }
//
//    @Override
//    public void stop() throws Exception {
//        super.stop();
//        PacketCapture capture = PacketCapture.getInstance();
//        capture.setRun(false);
//        capture = null;
//    }
//}
