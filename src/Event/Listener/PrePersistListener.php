<?php

namespace App\Event\Listener;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\EventSubscriber\EventSubscriberInterface;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Events;

class PrePersistListener implements EventSubscriberInterface
{

    /**
     * @return array
     */
    public function getSubscribedEvents(): array
    {
        return [Events::prePersist];
    }

    /**
     * @param PrePersistEventArgs $args
     * @return void
     */
    public function prePersist(PrePersistEventArgs $args): void
    {
        $entity = $args->getObject();

        $now = new \DateTime();

        if ($entity instanceof User) {
            if (!$entity->getCreatedAt()) {
                $entity->setCreatedAt($now);
            }
            $entity->setUpdatedAt($now);
        }
    }
}