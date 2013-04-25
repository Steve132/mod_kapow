<HTML>
   <HEAD>
      <TITLE>450 Invalid PoW</TITLE>
   </HEAD>
   <BODY ONLOAD='document.links[0].replace = true; Solve(document.links[0]);'>
      <H1>Invalid PoW</H1>
      <P>
         The requested URL did not have a valid Proof-of-Work attached and a
         valid solution is required to access this resource.<BR>
         If you are reading this page, it is likely that you do not have JavaScript enabled.<BR>
         <BR>
         If you would to access the content, please enable JavaScript and click the following link:
         <?php
         // Print the URL.
         // window.location.replace(document.links[0].href);
         $URL    = $_SERVER['REQUEST_URI'];
         echo "<A HREF='$URL'>$URL</A>"; ?>

      </P>
      <HR>
   </BODY>
</HTML>
