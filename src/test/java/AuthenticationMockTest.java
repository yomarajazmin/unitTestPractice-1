import authentication.Authentication;
import authentication.CredentialsService;
import authentication.PermissionService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;

public class AuthenticationMockTest {
    CredentialsService credentialsService = Mockito.mock(CredentialsService.class);
    PermissionService permissionService = Mockito.mock(PermissionService.class);

    @Test
    @Timeout(value = 1)
    public void verifyAuthenticationAdminUserMock(){
        Mockito.when(credentialsService.isValidCredential("testUser","123")).thenReturn(true);
        Mockito.when(permissionService.getPermission("testUser")).thenReturn("CRUD");

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);
        authentication.setPermissionService(permissionService);

        String expectedResult = "CRUD";
        String actualResult = authentication.login("testUser", "123");
        Assertions.assertEquals("user authenticated successfully with permission: ["+expectedResult+"]",actualResult,"ERROR! the result was not the expected");

        Mockito.verify(credentialsService).isValidCredential("testUser","123");
        Mockito.verify(permissionService).getPermission("testUser");
    }

    @Test
    public void verifyAuthenticationExistentUserCRUPermissionMock(){
        Mockito.when(credentialsService.isValidCredential("testUser","123")).thenReturn(true);
        Mockito.when(permissionService.getPermission("testUser")).thenReturn("CRU");

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);
        authentication.setPermissionService(permissionService);

        String expectedResult = "CRU";
        String actualResult = authentication.login("testUser", "123");
        Assertions.assertEquals("user authenticated successfully with permission: ["+expectedResult+"]",actualResult,"ERROR! the result was not the expected");

        Mockito.verify(credentialsService).isValidCredential("testUser","123");
        Mockito.verify(permissionService).getPermission("testUser");
    }

    @Test
    public void verifyAuthenticationExistentUserRPermissionMock(){
        Mockito.when(credentialsService.isValidCredential("testUser","123")).thenReturn(true);
        Mockito.when(permissionService.getPermission("testUser")).thenReturn("R");

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);
        authentication.setPermissionService(permissionService);

        String expectedResult = "R";
        String actualResult = authentication.login("testUser", "123");
        Assertions.assertEquals("user authenticated successfully with permission: ["+expectedResult+"]",actualResult,"ERROR! the result was not the expected");

        Mockito.verify(credentialsService).isValidCredential("testUser","123");
        Mockito.verify(permissionService).getPermission("testUser");
    }

    @Test
    public void verifyAuthenticationNotRegisteredUserMock(){
        Mockito.when(credentialsService.isValidCredential("testUser","123")).thenReturn(false);

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);

        String actualResult = authentication.login("testUser", "123");
        Assertions.assertEquals("user or password incorrect", actualResult, "ERROR! the user exists");

        Mockito.verify(credentialsService).isValidCredential("testUser","123");
    }

    @Test
    public void verifyAuthenticationInvalidPassMock(){
        Mockito.when(credentialsService.isValidCredential("testUser","1234")).thenReturn(false);

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);

        String actualResult = authentication.login("testUser", "1234");
        Assertions.assertEquals("user or password incorrect", actualResult, "ERROR! the user exists");

        Mockito.verify(credentialsService).isValidCredential("testUser","1234");
    }

    @Test
    public void verifyAuthenticationEmptyUserMock(){
        Mockito.when(credentialsService.isValidCredential("","123")).thenReturn(false);

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);

        String actualResult = authentication.login("", "123");
        Assertions.assertEquals("user or password incorrect", actualResult, "ERROR! the user exists");

        Mockito.verify(credentialsService).isValidCredential("","123");
    }

    @Test
    public void verifyAuthenticationEmptyPassMock(){
        Mockito.when(credentialsService.isValidCredential("testUser","")).thenReturn(false);

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);

        String actualResult = authentication.login("testUser", "");
        Assertions.assertEquals("user or password incorrect", actualResult, "ERROR! the user exists");

        Mockito.verify(credentialsService).isValidCredential("testUser","");
    }

    @Test
    public void verifyAuthenticationEmptyDataMock(){
        Mockito.when(credentialsService.isValidCredential("","")).thenReturn(false);

        Authentication authentication= new Authentication();
        authentication.setCredentialsService(credentialsService);

        String actualResult = authentication.login("", "");
        Assertions.assertEquals("user or password incorrect", actualResult, "ERROR! the user exists");

        Mockito.verify(credentialsService).isValidCredential("","");
    }
}
