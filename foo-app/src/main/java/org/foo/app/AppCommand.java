/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.foo.app;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.foo.app.database.DatabaseInterface;
import org.onosproject.cli.AbstractShellCommand;
import org.apache.karaf.shell.api.action.Argument;

/**
 * Sample Apache Karaf CLI command
 */
@Service
@Command(scope = "onos", name = "database",
         description = "DataBase comunications")
public class AppCommand extends AbstractShellCommand {

    @Option(name = "-t", aliases = { "--table" }, description = "specifies a database table to act on (use with flag --action)", required = false, multiValued = false)
    String table = null;

    @Argument(index = 0, name = "arg1", description = "", required = false)
    String arg_1 = null;

    @Override
    protected void doExecute() {
        if (table != null){
            tableRead();
        }
    }

    private void tableRead(){
        DatabaseInterface db = get(DatabaseInterface.class);
        log.info("Read on "+table);
        db.readTable(table);
    }

}
