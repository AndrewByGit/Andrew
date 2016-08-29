package andrew;/**
 * Created by 安德魯 on 2016/8/29.
 */

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;


import java.io.File;
import java.io.IOException;
import java.util.Date;

public class Sample1 extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    private String text="";
//    private Desktop desktop = Desktop.getDesktop();

    final TextArea textArea = new TextArea();

    @Override
    public void start(Stage primaryStage) {

        final FileChooser fileChooser = new FileChooser();
        final Button openButton = new Button("Open a Pcap...");
        openButton.setOnAction(
                new EventHandler<ActionEvent>() {
                    @Override
                    public void handle(final ActionEvent e) {
                        File file = fileChooser.showOpenDialog(primaryStage);
                        if (file != null) {
                            openFile(file);
                        }
                    }
                });

        final GridPane inputGridPane = new GridPane();

        GridPane.setConstraints(openButton, 0, 0);
        inputGridPane.setHgap(6);
        inputGridPane.setVgap(6);
        inputGridPane.getChildren().add(openButton);

        final Pane rootGroup = new VBox(12);
        rootGroup.getChildren().addAll(inputGridPane,textArea);
//        rootGroup.setPadding(new Insets(12, 12, 12, 12));
        primaryStage.setScene(new Scene(rootGroup));
        primaryStage.setWidth(550);
        primaryStage.setHeight(550);
        primaryStage.show();

        Text text=new Text("Hello World");
//        text.setX(50);
//        text.setY(50);

//        Group group=new Group();
//        group.getChildren().add(text);

//        Scene scene = new Scene(group);
//        primaryStage.setTitle("Hello world");
//        primaryStage.setWidth(350);
//        primaryStage.setHeight(250);
//        primaryStage.setScene(scene);
//        primaryStage.setResizable(true);
//        primaryStage.show();
    }

    private void openFile(File file) {
        try {
//            desktop.open(file);
            StringBuilder errbuf=new StringBuilder();
            Pcap pcap= Pcap.openOffline(file.getAbsolutePath() ,errbuf);

            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

                public void nextPacket(PcapPacket packet, String user) {

                    System.out.println("Header=="+packet.getCaptureHeader());
//                    System.out.println("Packet=="+packet);
                    text += packet.getCaptureHeader().caplen()+"\n";
                    textArea.setText(text);
                    System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                            new Date(packet.getCaptureHeader().timestampInMillis()),
                            packet.getCaptureHeader().caplen(),  // Length actually captured
                            packet.getCaptureHeader().wirelen(), // Original length
                            user                                 // User supplied object
                    );

                }
            };

            // capture first 10 packages
            pcap.loop(20, jpacketHandler, "jNetPcap");
            pcap.close();
            System.out.println("End");
        } catch (Exception ex) {
            System.out.println(ex.toString());
//            Logger.getLogger(
//                    FileChooserSample.class.getName()).log(
//                    Level.SEVERE, null, ex
//            );
        }
    }
}
