package org.foo.app.database;

import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.*;
import java.util.*;

// This class is an OSGi framework component that provides a sevice implemented by the DatabaseInterface.
// The attribute 'immediate = true' indicates that this component will be activated immediately upon registration in the OSGi framework
@Component(immediate = true,
    service = {DatabaseInterface.class}
)

public class SnortDatabase implements DatabaseInterface{

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference
    private DataSource dataSource;

    @Activate
    protected void activate(){
        log.info("Started Snort DB");
    }

    @Override
    public void readTable(String table){

        String readTableString = "select * from " + table;


        try(Connection con = dataSource.getConnection();
            PreparedStatement prepStmt = con.prepareStatement(readTableString)){

            ResultSet rs = prepStmt.executeQuery();
            ResultSetMetaData meta = rs.getMetaData();


            System.out.println("Colum names:");
            for(int i = 1; i <= meta.getColumnCount(); i++){
                System.out.print(meta.getColumnName(i).toString()+";");
            }
            System.out.println();

            while (rs.next()) {
                for(int i = 1; i <= meta.getColumnCount(); i++) {
                    System.out.print(rs.getString(i)+"; ");
                }
                System.out.println();
            }
            System.out.println();



        } catch (SQLException throwables) {
            log.info("ERROR reading table "+table+" from DataBase. "+getClass());
            throwables.printStackTrace();
        }
    }
}
