<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sign up / Successfully - Workshop For Beginners</title>
    <link href="../assets/css/bootstrap.min.css" rel="stylesheet" />
    <link rel="stylesheet" href="../assets/icons/bootstrap-icons.css" />
</head>

<body>
    <div class="container">
        <div class="row text-center mt-2">
            <div class="col">
                <div class="p-5">
                    <i class="bi-check-circle" style="font-size: 6rem; color: #0d6efd"></i>
                </div>
                <h2 class="text-primary">Congratulations! Registration Successfully!</h2>
                <p>
                    Please check your email and click link inside your email for
                    activation your new account.
                </p>
                <div class="text-center m-5">
                    <a href="<?php echo base_url('auth/login') ?>" class="btn btn-primary btn-lg"><i class="bi-person-circle"></i> Sign in</a>
                    <a href="<?php echo base_url('') ?>" class="btn btn-link link-secondary"><i class="bi-house"></i> Homepage</a>
                </div>
            </div>
        </div>
    </div>
    <script src="../assets/js/bootstrap.bundle.min.js"></script>
</body>

</html>