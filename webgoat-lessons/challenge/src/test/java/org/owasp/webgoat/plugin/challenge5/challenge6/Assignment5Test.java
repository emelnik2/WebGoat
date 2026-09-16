package org.owasp.webgoat.plugin.challenge5.challenge6;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.owasp.webgoat.assignments.AssignmentEndpointTest;
import org.owasp.webgoat.assignments.AttackResult;
import org.owasp.webgoat.plugin.Flag;
import org.owasp.webgoat.session.DatabaseUtilities;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Tests for the SQL injection fix in Assignment5.login().
 *
 * The login() method previously concatenated username_login and password_login
 * directly into the SQL string.  The fix replaces this with a parameterized
 * PreparedStatement using ? placeholders bound via setString(), so that
 * user-supplied values are always treated as data, never as SQL syntax.
 *
 * These tests use a real in-memory HSQLDB database (the same engine used by
 * WebGoat at runtime) injected into DatabaseUtilities' static connection map
 * via reflection, so that actual SQL execution is validated – not just mocked.
 */
@RunWith(MockitoJUnitRunner.class)
public class Assignment5Test extends AssignmentEndpointTest {

    private static final String TEST_USER = "unit-test-a5";

    private Assignment5 assignment5;
    private Connection testConnection;

    /**
     * Retrieve the randomised table name that Assignment5 set at class-load
     * time, create that table in the in-memory DB, and inject the connection
     * into DatabaseUtilities so that the static getConnection() call inside
     * login() picks it up without needing a real WebgoatContext.
     */
    @Before
    public void setup() throws Exception {
        assignment5 = new Assignment5();
        init(assignment5);
        new Flag().initFlags();

        // Boot an in-memory HSQLDB instance (same dialect as WebGoat's runtime DB)
        Class.forName("org.hsqldb.jdbcDriver");
        testConnection = DriverManager.getConnection(
                "jdbc:hsqldb:mem:" + TEST_USER + ";shutdown=true", "sa", "");

        // Discover the randomised table name Assignment5 uses
        String tableName = (String) ReflectionTestUtils.getField(
                Assignment5.class, "USERS_TABLE_NAME");

        // Create the table and seed it with the same rows as createChallengeTable()
        Statement st = testConnection.createStatement();
        st.executeUpdate("CREATE TABLE IF NOT EXISTS " + tableName
                + " (userid varchar(250), email varchar(30), password varchar(30))");
        // Insert 'Larry' with capital L to match the username guard in login()
        // (which requires !"Larry".equals(username_login)), then the query
        // searches by userid = ? where ? is bound to "Larry".
        st.executeUpdate("INSERT INTO " + tableName
                + " VALUES ('Larry', 'larry@webgoat.org', 'larryknows')");
        st.executeUpdate("INSERT INTO " + tableName
                + " VALUES ('tom',   'tom@webgoat.org',   'thisisasecretfortomonly')");
        st.close();

        // Pre-populate DatabaseUtilities' static connection map so the
        // static call getConnection(webSession) returns our test connection
        // without attempting to open a real JDBC URL.
        @SuppressWarnings("unchecked")
        Map<String, Connection> connections = (Map<String, Connection>)
                ReflectionTestUtils.getField(DatabaseUtilities.class, "connections");
        connections.put(TEST_USER, testConnection);

        // Mark the DB as already-built to prevent CreateDB from running
        @SuppressWarnings("unchecked")
        Map<String, Boolean> dbBuilt = (Map<String, Boolean>)
                ReflectionTestUtils.getField(DatabaseUtilities.class, "dbBuilt");
        dbBuilt.put(TEST_USER, Boolean.TRUE);

        // Make webSession return our test user name so the static lookup finds our connection
        when(webSession.getUserName()).thenReturn(TEST_USER);
    }

    @After
    public void teardown() throws Exception {
        // Remove the test connection from the static map to avoid side-effects
        @SuppressWarnings("unchecked")
        Map<String, Connection> connections = (Map<String, Connection>)
                ReflectionTestUtils.getField(DatabaseUtilities.class, "connections");
        connections.remove(TEST_USER);

        @SuppressWarnings("unchecked")
        Map<String, Boolean> dbBuilt = (Map<String, Boolean>)
                ReflectionTestUtils.getField(DatabaseUtilities.class, "dbBuilt");
        dbBuilt.remove(TEST_USER);

        if (testConnection != null && !testConnection.isClosed()) {
            testConnection.close();
        }
    }

    // ------------------------------------------------------------------
    // Positive path: valid credentials succeed
    // ------------------------------------------------------------------

    /**
     * The correct password for larry must complete the challenge.
     * This validates that the parameterized fix still lets legitimate logins work.
     */
    @Test
    public void validCredentialsCompleteChallenge() throws Exception {
        AttackResult result = assignment5.login("Larry", "larryknows");
        assertTrue("Correct credentials should complete the challenge",
                result.isLessonCompleted());
    }

    // ------------------------------------------------------------------
    // Negative path: wrong credentials fail
    // ------------------------------------------------------------------

    /**
     * An incorrect password must not complete the challenge.
     */
    @Test
    public void wrongPasswordFails() throws Exception {
        AttackResult result = assignment5.login("Larry", "wrongpassword");
        assertFalse("Wrong password must not complete the challenge",
                result.isLessonCompleted());
    }

    // ------------------------------------------------------------------
    // SQL injection prevention
    // ------------------------------------------------------------------

    /**
     * Classic tautology injection in the password field:
     *   ' OR '1'='1
     *
     * With the old string-concatenated query this would have produced:
     *   SELECT password FROM ... WHERE userid = 'Larry' AND password = '' OR '1'='1'
     * which evaluates to TRUE for every row, granting access without knowing
     * the real password.
     *
     * With the parameterized fix the payload is a literal string value.
     * It will not match the stored password "larryknows", so the query
     * returns zero rows and the challenge is NOT completed.
     */
    @Test
    public void tautologyInjectionInPasswordIsBlocked() throws Exception {
        AttackResult result = assignment5.login("Larry", "' OR '1'='1");
        assertFalse("SQL tautology injection in password must not bypass authentication",
                result.isLessonCompleted());
    }

    /**
     * Tautology injection with a trailing SQL comment:
     *   ' OR 1=1 --
     *
     * The comment would have dropped the closing quote and any trailing
     * conditions in the unparameterized query.  With parameterization the
     * full string (including the dashes) is treated as a literal value.
     */
    @Test
    public void tautologyWithCommentInjectionIsBlocked() throws Exception {
        AttackResult result = assignment5.login("Larry", "' OR 1=1 --");
        assertFalse("Tautology with comment injection must not bypass authentication",
                result.isLessonCompleted());
    }

    /**
     * Single-quote injection: supplying a lone apostrophe as the password.
     * In a concatenated query this would have broken the SQL syntax.
     * With parameterization it is handled safely as a literal character.
     */
    @Test
    public void singleQuoteInPasswordIsSafelyHandled() throws Exception {
        AttackResult result = assignment5.login("Larry", "'");
        assertFalse("Single-quote injection must not bypass authentication",
                result.isLessonCompleted());
    }

    /**
     * UNION-based injection in the password:
     *   ' UNION SELECT password FROM users --
     * With parameterization this entire string is treated as a literal value
     * and will not match the stored password.
     */
    @Test
    public void unionInjectionInPasswordIsBlocked() throws Exception {
        AttackResult result = assignment5.login("Larry", "' UNION SELECT password FROM users --");
        assertFalse("UNION injection must not bypass authentication",
                result.isLessonCompleted());
    }

    // ------------------------------------------------------------------
    // Guard checks: blank / non-Larry inputs are rejected before DB access
    // ------------------------------------------------------------------

    /**
     * An empty username must be rejected with a failure result before any
     * SQL query is executed.
     */
    @Test
    public void blankUsernameIsRejected() throws Exception {
        AttackResult result = assignment5.login("", "somepassword");
        assertFalse("Blank username must not succeed", result.isLessonCompleted());
    }

    /**
     * An empty password must be rejected with a failure result before any
     * SQL query is executed.
     */
    @Test
    public void blankPasswordIsRejected() throws Exception {
        AttackResult result = assignment5.login("Larry", "");
        assertFalse("Blank password must not succeed", result.isLessonCompleted());
    }

    /**
     * The lesson only accepts the username "Larry".  Other known users (e.g.
     * "tom") must be rejected by the username guard before the DB is consulted.
     */
    @Test
    public void nonLarryUsernameIsRejected() throws Exception {
        AttackResult result = assignment5.login("tom", "thisisasecretfortomonly");
        assertFalse("Non-Larry username must not succeed", result.isLessonCompleted());
    }

    /**
     * A SQL injection payload used as the username (e.g. ' OR '1'='1) must be
     * rejected by the application-level username guard ("Larry" check) before
     * the SQL statement is even prepared, preventing the injection from reaching
     * the database at all.
     */
    @Test
    public void sqlInjectionAsUsernameIsRejectedByGuard() throws Exception {
        AttackResult result = assignment5.login("' OR '1'='1", "irrelevant");
        assertFalse("SQL injection payload as username must not succeed",
                result.isLessonCompleted());
    }
}
