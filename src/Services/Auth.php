<?php

namespace Lsr\Core\Auth\Services;

use Lsr\Core\Auth\Dto\UserRow;
use Lsr\Core\Auth\Exceptions\DuplicateEmailException;
use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Models\UserType;
use Lsr\Db\DB;
use Lsr\Interfaces\AuthInterface;
use Lsr\Interfaces\SessionInterface;
use Lsr\Logging\Exceptions\DirectoryCreationException;
use Lsr\Orm\Exceptions\ModelNotFoundException;
use Lsr\Orm\Exceptions\ValidationException;
use Nette\Security\Passwords;
use SensitiveParameter;

/**
 * @template T of User
 * @implements AuthInterface<T>
 */
class Auth implements AuthInterface
{

    /** @var T|null */
    protected ?User $loggedIn = null;

    /**
     * @param  SessionInterface  $session
     * @param  Passwords  $passwords
     * @param  class-string<T>  $userClass
     */
    public function __construct(
        private readonly SessionInterface $session,
        private readonly Passwords        $passwords,
        private readonly string           $userClass = User::class,
    ) {}

    public function __wakeup() : void {
        $this->init();
    }

    public function logout() : void {
        $this->session->delete('usr');
        $this->loggedIn = null;
    }

    /**
     * Check if the user is logged in and populate the static variable
     *
     * @return void
     * @throws ModelNotFoundException
     * @throws ValidationException
     * @throws DirectoryCreationException
     */
    public function init() : void {
        $this->loggedIn = null;
        /** @var string|null $usr */
        $usr = $this->session->get('usr');
        if (isset($usr)) {
            /** @var T|false $user */
            $user = unserialize($usr, ['allowed_classes' => true]);
            if ($user !== false) {
                $user->fetch(true);
                $this->setLoggedIn($user);
            }
        }
    }

    /**
     * Try to log in a user
     *
     * @param  string  $email
     * @param  string  $password
     * @param  bool  $remember  If true, set the SESSION lifespan to 30 days
     *
     * @return bool If the login was successful
     * @throws ValidationException
     */
    public function login(string $email, #[SensitiveParameter] string $password, bool $remember = false) : bool {
        $user = DB::select(($this->userClass)::TABLE, 'id_user, email, password')
                  ->where('[email] = %s', $email)
                  ->fetchDto(UserRow::class);
        if (!isset($user)) {
            return false; // User does not exist
        }
        if (!$this->passwords->verify($password, $user->password)) {
            return false; // Invalid password
        }
        $this->loggedIn = ($this->userClass)::get($user->id_user);

        if ($this->passwords->needsRehash($user->password)) {
            $this->loggedIn->password = $this->passwords->hash($password);
            $this->loggedIn->save();
        }
        $this->session->set('usr', serialize($this->loggedIn));
        if ($remember) {
            $this->session->setParams(
                time() + (3600 * 24 * 30)
            ); // 3600 seconds in an hour * 24 hours in a day * 30 days
        }
        return true;
    }

    /**
     * Register a new user
     *
     * @param  string  $email
     * @param  string  $password
     * @param  string  $name
     *
     * @return T|null
     * @throws DuplicateEmailException
     */
    public function register(string $email, string $password, string $name = '') : ?User {
        $check = DB::select(($this->userClass)::TABLE, 'COUNT(*)')
                   ->where('[email] = %s', $email)
                   ->fetchSingle();
        if ($check > 0) {
            throw new DuplicateEmailException('User with this email already exists');
        }

        $user = new ($this->userClass);
        $user->name = $name;
        $user->email = $email;
        $user->password = $this->passwords->hash($password);
        $user->type = UserType::getHostUserType() ?? (new UserType());
        if (property_exists($user, 'id_user_type')) {
            $user->id_user_type = $user->type->id ?? 1;
        }
        try {
            if ($user->insert()) {
                return $user;
            }
        } catch (ValidationException) {
            // TODO: Handle validation error
        }

        return null;
    }

    public function loggedIn() : bool {
        return isset($this->loggedIn);
    }

    /**
     * @return T|null
     */
    public function getLoggedIn() : ?User {
        return $this->loggedIn;
    }

    /**
     * @param  T  $loggedIn
     *
     * @return static
     */
    public function setLoggedIn(User $loggedIn) : static {
        $this->loggedIn = $loggedIn;
        $this->session->set('usr', serialize($this->loggedIn));
        return $this;
    }

    /**
     * Check if user is currently logged in and has specified right.
     *
     * @param  non-empty-string  $right
     *
     * @return bool
     */
    public function hasRight(string $right) : bool {
        if (!isset($this->loggedIn)) {
            return false;
        }
        return $this->loggedIn->hasRight($right);
    }

    /**
     * Get all current user's rights
     *
     * @return string[]
     */
    public function getRights() : array {
        if (!isset($this->loggedIn)) {
            return [];
        }
        return $this->loggedIn->getRights();
    }
}