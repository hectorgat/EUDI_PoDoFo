#include <podofo/podofo.h>

int main()
{
    try {

        PoDoFo::HelloWorld();

        string conformanceLevel = "Ades_B_B";
        string my_end = "my_end";
        string my_chain1 = "my_chain1";
        string my_signed = "my_signed";

        // Construct the object
        PdfRemoteSignDocumentSession session{
                conformanceLevel,                   // string
                "2.16.840.1.101.3.4.2.1",           // string
                "input/sample.pdf",                 // string
                "output/TestSignature001.pdf",      // string
                my_end,                             // string
                {my_chain1},                        // string array
                std::nullopt                        // string (optional)
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
