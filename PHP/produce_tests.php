<?php
  $tests = Array();
  $tests["password"] = "salt";
  $tests["password2"] = "othersalt";
  $tests["somewhatlongpasswordstringthatIwanttotest"] = "1";
  $tests["p"] = "somewhatlongsaltstringthatIwanttotest";

  function generateTests($tests, $alg, $iterations) {
    echo "ALG = $alg\n";
    echo "ITER = $iterations\n";
    echo "\n\n";
    foreach ($tests as $password => $salt) {
      $result = hash_pbkdf2($alg, $password, $salt, $iterations);
      echo "(\"$password\", \"$salt\", \"$result\"),\n";
    }
    echo "\n\n";
  }

  generateTests($tests, "md5", 1000);
?>
