<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sign up - Workshop For Beginners</title>
  <link href="/assets/css/bootstrap.min.css" rel="stylesheet" />
</head>

<body>
  <div class="container">
    <div class="row text-center mt-5">
      <div class="col">
        <div class="w-100 p-2">
          <img style="width: 200px; border-radius: 10px;" src="../assets/img/logo.jpg" />
        </div>
        <h2 class="w-100">Create your account</h2>
      </div>
    </div>
    <div class="row mt-5 justify-content-center">
      <div class="col-md-8 col-lg-6">
        <div class="card">
          <div class="card-body">
            <form action="register" method="post">
              <div class="row mb-3">
                <div class="col-xs-12 col-sm-6">
                  <label for="inputFirstname" class="form-label">Firstname</label>
                  <input type="text" class="form-control" id="inputFirstname" name="firstname" aria-describedby="emailHelp" value="<?php echo set_value('firstname') ?>" />
                  <a style="color:#FF0000;"><?php echo form_error('firstname') ?></a>
                </div>
                <div class="col-xs-12 col-sm-6">
                  <label for="inputLastname" class="form-label">Lastname</label>
                  <input type="text" class="form-control" id="inputLastname" name="lastname" value="<?php echo set_value('lastname') ?>" />
                  <a style="color:#FF0000;"><?php echo form_error('lastname') ?></a>
                </div>
              </div>
              <div class="mb-3">
                <label for="inputEmail" class="form-label">Email address</label>
                <input type="email" class="form-control" id="inputEmail" name="email" aria-describedby="emailHelp" value="<?php echo set_value('email') ?>" />
                <a style="color:#FF0000;"><?php echo form_error('email') ?></a>
              </div>
              <div class="mb-3">
                <label for="inputPassword" class="form-label">Password</label>
                <input type="password" class="form-control" id="inputPassword" name="password" value="<?php echo set_value('') ?>" />
                <a style="color:#FF0000;"><?php echo form_error('password') ?></a>
              </div>
              <div class="mb-3">
                <label for="inputConfirmPassword" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" id="inputConfirmPassword" name="passconf" value="<?php echo set_value('') ?>" />
                <a style="color:#FF0000;"><?php echo form_error('passconf') ?></a>
              </div>
              <div class="form-check mb-3">
                <input type="checkbox" class="form-check-input" id="checkInformNewFeatures" />
                <label class="form-check-label" for="checkInformNewFeatures">Inform me about new features and updates.</label>
              </div>

              <button type="submit" class="btn btn-primary w-100">
                Confirm
              </button>

            </form>

            <hr />
            <div class="text-center">
              <a href="/" class="link-secondary">Go back to homepage</a>
            </div>

          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="../assets/js/bootstrap.bundle.min.js"></script>
</body>

</html>