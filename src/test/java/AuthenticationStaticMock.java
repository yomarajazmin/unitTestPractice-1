import authenticationStatic.Authentication;
import authenticationStatic.CredentialsStaticService;
import authenticationStatic.PermissionStaticService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class AuthenticationStaticMock {

    @Test
    @Timeout(value = 1)
    public void verifyAdminUserStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("testUser","123")).thenReturn(true);
        MockedStatic<PermissionStaticService> permissionStaticService = Mockito.mockStatic(PermissionStaticService.class);
        permissionStaticService.when(()->PermissionStaticService.getPermission("testUser")).thenReturn("CRUD");

        Authentication authentication = new Authentication();
        String expectedResult = "CRUD";
        String actualResult = authentication.login("testUser", "123");

        Assertions.assertEquals("user authenticated successfully with permission: ["+expectedResult+"]",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
        permissionStaticService.close();
    }

    @Test
    public void verifyCRUUserStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("testUser","123")).thenReturn(true);
        MockedStatic<PermissionStaticService> permissionStaticService = Mockito.mockStatic(PermissionStaticService.class);
        permissionStaticService.when(()->PermissionStaticService.getPermission("testUser")).thenReturn("CRU");

        Authentication authentication = new Authentication();
        String expectedResult = "CRU";
        String actualResult = authentication.login("testUser", "123");

        Assertions.assertEquals("user authenticated successfully with permission: ["+expectedResult+"]",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
        permissionStaticService.close();
    }

    @Test
    public void verifyRUserStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("testUser","123")).thenReturn(true);
        MockedStatic<PermissionStaticService> permissionStaticService = Mockito.mockStatic(PermissionStaticService.class);
        permissionStaticService.when(()->PermissionStaticService.getPermission("testUser")).thenReturn("R");

        Authentication authentication = new Authentication();
        String expectedResult = "R";
        String actualResult = authentication.login("testUser", "123");

        Assertions.assertEquals("user authenticated successfully with permission: ["+expectedResult+"]",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
        permissionStaticService.close();
    }

    @Test
    public void verifyNotRegisteredUserStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("testUser","123")).thenReturn(false);

        Authentication authentication = new Authentication();
        String actualResult = authentication.login("testUser", "123");

        Assertions.assertEquals("user or password incorrect",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
    }

    @Test
    public void verifyInvalidPasswordStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("testUser","1234")).thenReturn(false);

        Authentication authentication = new Authentication();
        String actualResult = authentication.login("testUser", "1234");

        Assertions.assertEquals("user or password incorrect",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
    }

    @Test
    public void verifyEmptyUserNameStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("","1234")).thenReturn(false);

        Authentication authentication = new Authentication();
        String actualResult = authentication.login("", "1234");

        Assertions.assertEquals("user or password incorrect",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
    }

    @Test
    public void verifyEmptyPasswordStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("testUser","")).thenReturn(false);

        Authentication authentication = new Authentication();
        String actualResult = authentication.login("testUser", "");

        Assertions.assertEquals("user or password incorrect",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
    }

    @Test
    public void verifyEmptyDataStaticMock(){
        MockedStatic<CredentialsStaticService> credentialsStaticService = Mockito.mockStatic(CredentialsStaticService.class);
        credentialsStaticService.when(()->CredentialsStaticService.isValidCredential("","")).thenReturn(false);

        Authentication authentication = new Authentication();
        String actualResult = authentication.login("", "");

        Assertions.assertEquals("user or password incorrect",actualResult,"ERROR! The result is not the expected");
        credentialsStaticService.close();
    }
}
