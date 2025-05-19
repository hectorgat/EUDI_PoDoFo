#include <podofo/podofo.h>

int main()
{
    try {

        PoDoFo::HelloWorld();

        string conformanceLevel = "ADES_B_B";
        string my_end = "MIICmDCCAh+gAwIBAgIUIGYtzcs9IBXguB9P0riuz8l+3NgwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI1MDMyMTIyMDUxM1oXDTI3MDMyMTIyMDUxMlowVTEdMBsGA1UEAwwURmlyc3ROYW1lIFRlc3RlclVzZXIxEzARBgNVBAQMClRlc3RlclVzZXIxEjAQBgNVBCoMCUZpcnN0TmFtZTELMAkGA1UEBhMCRkMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATKfz322k66qo078TlOuj7DnCIysLH4Luq/rJXNXtlS5WvGOVNIc95blK/XRIgx8/Q0SYHrXwumDOaJxKZzs222o4HFMIHCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUs2y4kRcc16QaZjGHQuGLwEDMlRswHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBRwUXIdDj4Rr+AfehggZXvcNj9wUTAOBgNVHQ8BAf8EBAMCBkAwCgYIKoZIzj0EAwIDZwAwZAIwUH8UEK/Vc+EDC4ZrRwBPpOCeJC5+9pky0hIyghFpaAOFUSsrqFjRxF9BlP/p1kNmAjA3B8sBJKNnlyEEHd0h+E6gaj5p/rgzj+kVX/30h8oZtAMpe1oamOGYhoLiZwmJH7Y=";
        string my_chain1 = "MIIDHTCCAqOgAwIBAgIUVqjgtJqf4hUYJkqdYzi+0xwhwFYwCgYIKoZIzj0EAwMwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTIzMDkwMTE4MzQxN1oXDTMyMTEyNzE4MzQxNlowXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFg5Shfsxp5R/UFIEKS3L27dwnFhnjSgUh2btKOQEnfb3doyeqMAvBtUMlClhsF3uefKinCw08NB31rwC+dtj6X/LE3n2C9jROIUN8PrnlLS5Qs4Rs4ZU5OIgztoaO8G9o4IBJDCCASAwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSzbLiRFxzXpBpmMYdC4YvAQMyVGzAWBgNVHSUBAf8EDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUs2y4kRcc16QaZjGHQuGLwEDMlRswDgYDVR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDaAAwZQIwaXUA3j++xl/tdD76tXEWCikfM1CaRz4vzBC7NS0wCdItKiz6HZeV8EPtNCnsfKpNAjEAqrdeKDnr5Kwf8BA7tATehxNlOV4Hnc10XO1XULtigCwb49RpkqlS2Hul+DpqObUs";
        string my_signed = "MEUCIQCpel09QAFtK/fPUvn+Nhx4VPH7Fm+vspv/UXluxXSKBAIge68SlU0JHVJCbKABh1GpNEiU2gD9sMVaWtLBv3Vb7kE=";

        // Construct the object
        PdfRemoteSignDocumentSession session{
                conformanceLevel,                   // string
                "2.16.840.1.101.3.4.2.1",           // string
                "input/sample.pdf",                 // string
                "output/TestSignature001.pdf",      // string
                my_end,                             // string
                {my_chain1},                        // string array
                std::nullopt,                       // string (optional)
                "my label"                          // string (optional)
        };
        session.printState();                       //Just prints info

        string urlEncodedHash = session.beginSigning();

        auto signedHash = my_signed;                // string

        session.finishSigning(signedHash);


    }
    catch (const std::exception& e) {
        cout << "\n=== Error in Application ===" << endl;
        cout << "Error: " << e.what() << endl;
        return 1;
    }




    return 0;
}
