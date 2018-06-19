/*
 * Copyright 2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.pivotal.ecosystem.greenplum.broker.database;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.credhub.core.CredHubOperations;
import org.springframework.credhub.support.CredentialDetails;
import org.springframework.credhub.support.SimpleCredentialName;
import org.springframework.credhub.support.json.JsonCredential;
import org.springframework.credhub.support.json.JsonCredentialRequest;
import org.springframework.credhub.support.permissions.CredentialPermission;
import static org.springframework.credhub.support.permissions.Operation.DELETE;
import static org.springframework.credhub.support.permissions.Operation.READ;
import static org.springframework.credhub.support.permissions.Operation.READ_ACL;
import static org.springframework.credhub.support.permissions.Operation.WRITE;
import static org.springframework.credhub.support.permissions.Operation.WRITE_ACL;

import org.springframework.stereotype.Component;
import io.pivotal.ecosystem.greenplum.broker.util.Utils;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Component
public class Role {
	
	@Autowired
	private GreenplumDatabase greenplum;
	
	@Autowired
	CredHubOperations credHubOperations;
	
	private Results results = new Results();

	private class Results extends HashMap<String, String> {
	}
	
    public void createRoleForInstance(String instanceId) throws SQLException {
        Utils.checkValidUUID(instanceId);
        greenplum.executeUpdate("CREATE ROLE \"" + instanceId + "\" LOGIN");
        greenplum.executeUpdate("ALTER DATABASE \"" + instanceId + "\" OWNER TO \"" + instanceId + "\"");
        greenplum.executeUpdate("alter role \"" + instanceId + "\" with CREATEEXTTABLE (type='readable',protocol='gpfdist')");
    }

    public void deleteRole(String instanceId) throws SQLException {
        Utils.checkValidUUID(instanceId);
        greenplum.executeUpdate("DROP ROLE IF EXISTS \"" + instanceId + "\"");
    }

    public String bindRoleToDatabase(String dbInstanceId) throws SQLException {
        Utils.checkValidUUID(dbInstanceId);
        String passwd="";
        	
        if (!results.containsKey(dbInstanceId)) {
	        SecureRandom random = new SecureRandom();
	        passwd = new BigInteger(130, random).toString(32);
	
	        greenplum.executeUpdate("ALTER ROLE \"" + dbInstanceId + "\" LOGIN password '" + passwd + "'");
        } else 
        		passwd = results.get(dbInstanceId);
        return passwd;
    }

    public void unBindRoleFromDatabase(String dbInstanceId) throws SQLException{
        Utils.checkValidUUID(dbInstanceId);
        greenplum.executeUpdate("ALTER ROLE \"" + dbInstanceId + "\" NOLOGIN");
    }
    
    /**
     * @todo fill in credhub integration
     * 
     * @param value
     * @param results
     * @return
     */
    private CredentialDetails<JsonCredential> writeCredentials(Map<String, Object> value, Results results) {
		try {
			JsonCredentialRequest request = JsonCredentialRequest.builder()
					.overwrite(true)
					.name(new SimpleCredentialName("spring-credhub", "gp_broker", "credentials_json"))
					.value(value)
					.permission(CredentialPermission.builder()
							.app("gp_broker")
							.operation(READ)
							.operation(WRITE)
							.build())
					.build();

			CredentialDetails<JsonCredential> credentialDetails = credHubOperations.write(request);
			saveCreds("Successfully wrote credentials: ", credentialDetails.toString());

			return credentialDetails;
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
    
    private void saveCreds(String key) {
		saveCreds(key, null);
	}

	private void saveCreds(String key, String secret) {
		results.put(key, secret);
	}
}
